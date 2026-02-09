//! gRPC service implementations.

pub mod auth_interceptor;
pub mod sbom_server;

#[allow(clippy::all)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/artifact_keeper.sbom.v1.rs"));
}

pub use generated::*;
