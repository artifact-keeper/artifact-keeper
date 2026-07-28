//! Typed curation rule evaluators (#2947 epic).
//!
//! Each submodule owns the evaluation logic for one `rule_type` of
//! `curation_rules` and stays free of database dependencies so it can be
//! unit-tested in isolation. The dispatch seam in
//! [`crate::services::curation_service::CurationService::evaluate_typed_rule`]
//! routes a rule + package context to the matching evaluator; every evaluator
//! renders a [`crate::models::curation::CurationDecision`].
//!
//! Currently implemented:
//! - [`publisher_trust`] — trusted-publisher allowlisting (issue #2948),
//!   backed by [`publisher_source`] (provenance-labeled publisher identity
//!   extraction).
//! - [`popularity`] — download-count threshold + typo-squat detection
//!   (issue #2949), backed by [`popularity_source`] (pluggable download-count
//!   providers) and [`typosquat`] (lexical-distance matching).

pub mod popularity;
pub mod popularity_source;
pub mod publisher_source;
pub mod publisher_trust;
pub mod typosquat;
