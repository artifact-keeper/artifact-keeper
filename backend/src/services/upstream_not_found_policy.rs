//! Per-repository policy for a definitive upstream 404/410 on a proxy path
//! (#4640).
//!
//! When a `Remote` (proxy) repository revalidates a cached mutable entry and
//! upstream answers **404** or **410**, the default behaviour deletes the
//! cached body and writes a negative-cache marker. For deployments that use the
//! proxy cache as a continuity copy of an external registry that is exactly the
//! wrong moment to throw content away: the bytes are local, only upstream has
//! stopped serving them.
//!
//! `on_upstream_not_found` makes that a per-repository choice:
//!
//! * [`OnUpstreamNotFound::Delete`] — the default, and today's behaviour:
//!   delete the cached body and negative-cache the path.
//! * [`OnUpstreamNotFound::Keep`] — leave the cached body in place, do not
//!   write a marker, and serve the cached copy. Paths that were never cached
//!   still negative-cache, so a hot loop of misses does not hammer upstream.
//!
//! The vocabulary (`keep` / `delete`) mirrors the planned `on_upstream_delete`
//! policy for mirror repositories (#3990), so the two can share documentation.
//!
//! The value is stored as one `repository_config` row
//! (`key = 'on_upstream_not_found'`), like `cache_ttl_secs` (#3832), so no
//! migration is required and an unset row means the default.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a `Remote` repository does when upstream answers 404/410 for a path
/// that has a cached positive body (#4640).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OnUpstreamNotFound {
    /// Keep the cached copy and serve it; do not delete the body and do not
    /// write a negative-cache marker. A path with no cached body still
    /// negative-caches.
    Keep,
    /// Delete the cached copy and negative-cache the path. The default, and
    /// the behaviour of every release before #4640.
    #[default]
    Delete,
}

impl OnUpstreamNotFound {
    /// The `repository_config.key` this policy is stored under.
    pub const CONFIG_KEY: &'static str = "on_upstream_not_found";

    /// Canonical lowercase spelling, as stored and on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Delete => "delete",
        }
    }

    /// Parse the stored/wire spelling. A blank, missing or unrecognized value
    /// is the default (`delete`), mirroring how `cache_ttl_secs` degrades to
    /// the classifier default rather than failing a read on dead state.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case(Self::Keep.as_str()) => Self::Keep,
            _ => Self::Delete,
        }
    }

    /// Whether this policy serves a cached copy on a definitive upstream miss.
    pub const fn keeps(self) -> bool {
        matches!(self, Self::Keep)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_delete() {
        assert_eq!(OnUpstreamNotFound::default(), OnUpstreamNotFound::Delete);
        assert!(!OnUpstreamNotFound::default().keeps());
    }

    #[test]
    fn parse_recognizes_keep_case_insensitively_and_trims() {
        for raw in ["keep", "KEEP", "Keep", "  keep  "] {
            assert_eq!(
                OnUpstreamNotFound::parse(Some(raw)),
                OnUpstreamNotFound::Keep,
                "{raw:?} must parse as keep"
            );
        }
        assert!(OnUpstreamNotFound::parse(Some("keep")).keeps());
    }

    #[test]
    fn parse_degrades_unknown_and_absent_to_delete() {
        for raw in [
            None,
            Some(""),
            Some("   "),
            Some("delete"),
            Some("tombstone"),
        ] {
            assert_eq!(
                OnUpstreamNotFound::parse(raw),
                OnUpstreamNotFound::Delete,
                "{raw:?} must degrade to delete"
            );
        }
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for policy in [OnUpstreamNotFound::Keep, OnUpstreamNotFound::Delete] {
            assert_eq!(
                OnUpstreamNotFound::parse(Some(policy.as_str())),
                policy,
                "as_str/parse must round-trip"
            );
        }
    }

    #[test]
    fn serializes_to_lowercase_wire_values() {
        assert_eq!(
            serde_json::to_string(&OnUpstreamNotFound::Keep).unwrap(),
            "\"keep\""
        );
        assert_eq!(
            serde_json::to_string(&OnUpstreamNotFound::Delete).unwrap(),
            "\"delete\""
        );
        assert_eq!(
            serde_json::from_str::<OnUpstreamNotFound>("\"keep\"").unwrap(),
            OnUpstreamNotFound::Keep
        );
    }
}
