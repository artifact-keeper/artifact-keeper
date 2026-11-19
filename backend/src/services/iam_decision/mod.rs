//! The IAM decision function: decides permit, refuse or unavailable for a
//! principal, permission, resource and request context over an immutable
//! [`PolicySnapshot`].
//!
//! Nothing here is wired into request handling yet; the function is the single
//! decision point later shadow evaluation, inspection APIs and enforcement will
//! share. See the IAM epic (#4214).

pub mod context;
pub mod decide;
pub mod resource_index;
pub mod snapshot;

pub use context::{Caller, Principal, RequestContext};
pub use decide::{decide, Decision, Grant, RefusalClass, Unavailability};
pub use resource_index::read_resource_index;
pub use snapshot::{
    Ceiling, DecisionConditions, PolicySnapshot, RepositoryFacts, ResourceIndex, SnapshotBinding,
    SnapshotDeny, SnapshotGap, Truth,
};

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
