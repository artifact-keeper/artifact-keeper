//! Artifact Keeper - Backend Library
//!
//! Open-source artifact registry supporting 13+ package formats.

pub mod api;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod formats;
pub mod models;
pub mod services;
pub mod storage;

pub use config::Config;
pub use error::{AppError, Result};
