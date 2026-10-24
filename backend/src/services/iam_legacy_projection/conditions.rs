//! Parsing of the legacy `permissions.conditions` column.
//!
//! The only supported key is `allowed_cidrs`. A rule with the key applies only
//! to requests whose verified client IP is inside one of the listed ranges, and
//! an empty list therefore applies to no request at all. Anything else in the
//! column is reported, never interpreted as "unconditional".

use std::collections::BTreeSet;

use serde_json::Value;

use super::intent::Cidr;

/// When a legacy rule applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleCondition {
    /// No condition: applies to every request, including an unknown IP.
    Always,
    /// Applies inside these ranges only. An empty set applies nowhere.
    Cidrs(BTreeSet<Cidr>),
}

impl RuleCondition {
    pub fn never_applies(&self) -> bool {
        matches!(self, RuleCondition::Cidrs(c) if c.is_empty())
    }
}

/// Parse the raw column value. `Err` carries the reason, for a diagnostic.
pub fn parse_conditions(value: Option<&Value>) -> Result<RuleCondition, String> {
    let object = match value {
        None | Some(Value::Null) => return Ok(RuleCondition::Always),
        Some(Value::Object(map)) => map,
        Some(other) => return Err(format!("conditions must be an object, got {other}")),
    };
    if let Some(key) = object.keys().find(|k| k.as_str() != "allowed_cidrs") {
        return Err(format!("unsupported condition key `{key}`"));
    }
    let Some(list) = object.get("allowed_cidrs") else {
        return Ok(RuleCondition::Always);
    };
    let Value::Array(items) = list else {
        return Err("allowed_cidrs must be an array of strings".to_string());
    };
    let mut cidrs = BTreeSet::new();
    for item in items {
        let Value::String(text) = item else {
            return Err("allowed_cidrs must be an array of strings".to_string());
        };
        cidrs.insert(Cidr::parse(text)?);
    }
    Ok(RuleCondition::Cidrs(cidrs))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_empty_and_keyless_conditions_always_apply() {
        for v in [None, Some(json!(null)), Some(json!({}))] {
            assert_eq!(parse_conditions(v.as_ref()), Ok(RuleCondition::Always));
        }
    }

    #[test]
    fn cidrs_are_parsed_and_normalized() {
        let c = parse_conditions(Some(
            &json!({"allowed_cidrs": ["10.1.2.3/8", "192.168.0.0/16", "10.0.0.0/8"]}),
        ))
        .unwrap();
        let RuleCondition::Cidrs(set) = c else {
            panic!()
        };
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Cidr::parse("10.0.0.0/8").unwrap()));
    }

    #[test]
    fn an_empty_list_applies_nowhere() {
        let c = parse_conditions(Some(&json!({"allowed_cidrs": []}))).unwrap();
        assert!(c.never_applies());
        assert!(!RuleCondition::Always.never_applies());
    }

    #[test]
    fn malformed_conditions_are_errors_not_unconditional() {
        for bad in [
            json!("10.0.0.0/8"),
            json!([]),
            json!({"allowed_cidrs": "10.0.0.0/8"}),
            json!({"allowed_cidrs": [7]}),
            json!({"allowed_cidrs": ["nope"]}),
            json!({"allowed_cidrs": ["10.0.0.0/40"]}),
            json!({"allowed_cidrs": ["10.0.0.0/8"], "not_before": "2026-01-01T00:00:00Z"}),
            json!({"time": 1}),
        ] {
            assert!(parse_conditions(Some(&bad)).is_err(), "{bad}");
        }
    }
}
