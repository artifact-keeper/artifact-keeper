//! gRPC service implementations.

pub mod sbom_server;

#[allow(clippy::all)]
pub mod generated {
    include!("generated/artifact_keeper.sbom.v1.rs");
}

pub use generated::*;
