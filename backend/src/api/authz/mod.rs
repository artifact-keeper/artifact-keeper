//! IAM permission catalog and route-authorization declarations.
//!
//! This module defines the typed permission catalog, parses the authorization
//! declarations carried by OpenAPI operations, and keeps a registry of them
//! keyed by method and route. It is deliberately non-enforcing: no middleware
//! or handler consults it, and existing handler authorization remains
//! authoritative until the shadow-enforcement and cutover changes.
//! See `openspec/changes/iam-permission-catalog-and-route-guard`.

pub mod catalog;
pub mod declaration;
pub mod registry;

// Shared test support: used by tests in several shards, so the module itself is
// not shard-gated (its own tests are).
#[cfg(test)]
pub(crate) mod route_inventory;
