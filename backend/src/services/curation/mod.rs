//! Curation policy rule evaluators (#2947 epic).
//!
//! Each submodule is a self-contained evaluator for one curation rule type.
//! The curation service dispatch (owned by the foundation work for #2947)
//! selects the evaluator by the rule's `rule_type` and maps the module-local
//! decision enum onto the shared `CurationDecision`.

pub mod publisher_source;
pub mod publisher_trust;
