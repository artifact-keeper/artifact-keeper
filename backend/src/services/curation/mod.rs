//! Curation rule-type evaluators.
//!
//! Each rule type lives in its own submodule and exposes a self-contained
//! `evaluate` entry point plus whatever data sources it needs. The curation
//! foundation (`rule_type` discriminator + `config` JSONB dispatch on
//! `curation_rules`, epic #2947) calls into these evaluators; the evaluators
//! themselves stay free of database and model dependencies so they can be
//! unit-tested in isolation.
//!
//! Currently implemented:
//! - [`popularity`] — download-count threshold + typo-squat detection
//!   (issue #2949), backed by [`popularity_source`] (pluggable download-count
//!   providers) and [`typosquat`] (lexical-distance matching).

pub mod popularity;
pub mod popularity_source;
pub mod typosquat;
