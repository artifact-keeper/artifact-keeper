//! IAM permission catalog and route-authorization declarations.
//!
//! This module defines the typed permission catalog, parses the authorization
//! declarations carried by OpenAPI operations, and keeps a registry of them
//! keyed by method and route. It is deliberately non-enforcing: no middleware
//! or handler consults it, and existing handler authorization remains
//! authoritative until the shadow-enforcement and cutover changes.
//! Part of the IAM epic (#4214).

pub mod catalog;
pub mod declaration;
pub mod registry;
pub mod shadow_marker;

// Shared test support: used by tests in several shards, so the module itself is
// not shard-gated (its own tests are).
#[cfg(test)]
pub(crate) mod route_inventory;

// Shared support for the declaration table tests below. It holds no tests, so
// like `route_inventory` it is not shard-gated.
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod admin_declarations;
#[cfg(test)]
pub(crate) mod declaration_table;
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod identity_declarations;
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod project_group_declarations;
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod repository_declarations;
