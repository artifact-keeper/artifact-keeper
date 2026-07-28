//! Typed curation rule evaluators (#2947 foundation).
//!
//! Each submodule owns the evaluation logic for one `rule_type` of
//! `curation_rules`. The dispatch seam in
//! [`crate::services::curation_service::CurationService::evaluate_typed_rule`]
//! routes a rule + package context to the matching evaluator.

pub mod popularity;
pub mod publisher_trust;
