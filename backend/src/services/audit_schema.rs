//! Published audit-event JSON Schema + drift gate (#2413).
//!
//! `backend/schemas/audit-event.v1.schema.json` is the committed, machine-readable
//! contract for the exported audit stream. It lives inside the crate (so the
//! Docker build context carries it) and is embedded here with `include_str!` so
//! the running binary and the tests validate against the exact bytes that ship
//! in the repo.
//!
//! The enforcement is inverted from a generate-and-diff gate: rather than
//! regenerate the schema from the Rust types, a normal `--lib` test serializes
//! live [`AuditEventRecord`](crate::services::audit_export::AuditEventRecord)
//! instances (and one instance of every typed detail struct) and validates them
//! against the committed schema with a dependency-free JSON-Schema-subset
//! checker. If a Rust field is renamed, retyped, or dropped, the emitted JSON no
//! longer conforms and CI fails — so the typed payloads cannot silently diverge
//! from the published contract, which is exactly what the issue asks for. No new
//! runtime or dev dependency is pulled in for this.

/// The committed audit-event JSON Schema, embedded from the crate.
pub const SCHEMA_JSON: &str = include_str!("../../schemas/audit-event.v1.schema.json");

/// Parse the committed schema. Panics only if the committed file is not valid
/// JSON, which the self-consistency test catches in ordinary CI.
pub fn schema() -> serde_json::Value {
    serde_json::from_str(SCHEMA_JSON).expect("committed audit-event schema is valid JSON")
}

#[cfg(test)]
mod validator {
    //! A tiny JSON-Schema-subset validator: enough of draft 2020-12 to gate the
    //! audit envelope and its typed detail payloads without an external crate.
    //! Supported keywords: `$ref` (into `#/$defs/*`), `type` (string or array),
    //! `const`, `enum`, `required`, `properties`, `additionalProperties: false`,
    //! `anyOf`, and the `allOf` + `if`/`then` subset used for action
    //! discrimination.
    //! `format`, `minimum`, and descriptions are advisory and ignored.

    use serde_json::Value;

    /// Validate `instance` against `schema` (resolving `$ref`s against `root`).
    /// Returns a list of human-readable errors; empty means valid.
    pub fn validate(schema: &Value, instance: &Value, root: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate_at(schema, instance, root, "$", &mut errors);
        errors
    }

    fn resolve<'a>(reference: &str, root: &'a Value) -> Option<&'a Value> {
        // Only local `#/$defs/Name` refs are used by the committed schema.
        let name = reference.strip_prefix("#/$defs/")?;
        root.get("$defs")?.get(name)
    }

    fn type_matches(ty: &str, instance: &Value) -> bool {
        match ty {
            "string" => instance.is_string(),
            "integer" => instance.is_i64() || instance.is_u64(),
            "number" => instance.is_number(),
            "object" => instance.is_object(),
            "array" => instance.is_array(),
            "boolean" => instance.is_boolean(),
            "null" => instance.is_null(),
            _ => false,
        }
    }

    fn validate_at(
        schema: &Value,
        instance: &Value,
        root: &Value,
        path: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(Value::Array(parts)) = schema.get("allOf") {
            for part in parts {
                validate_at(part, instance, root, path, errors);
            }
        }

        if let Some(Value::Array(alternatives)) = schema.get("anyOf") {
            let matched = alternatives.iter().any(|alternative| {
                let mut alternative_errors = Vec::new();
                validate_at(alternative, instance, root, path, &mut alternative_errors);
                alternative_errors.is_empty()
            });
            if !matched {
                errors.push(format!("{path}: did not match anyOf alternatives"));
            }
        }

        if let Some(condition) = schema.get("if") {
            let mut condition_errors = Vec::new();
            validate_at(condition, instance, root, path, &mut condition_errors);
            if condition_errors.is_empty() {
                if let Some(then_schema) = schema.get("then") {
                    validate_at(then_schema, instance, root, path, errors);
                }
            }
        }

        if let Some(Value::String(reference)) = schema.get("$ref") {
            match resolve(reference, root) {
                Some(target) => validate_at(target, instance, root, path, errors),
                None => errors.push(format!("{path}: unresolved $ref {reference}")),
            }
            return;
        }

        if let Some(expected) = schema.get("const") {
            if instance != expected {
                errors.push(format!("{path}: expected const {expected}, got {instance}"));
            }
        }

        if let Some(Value::Array(choices)) = schema.get("enum") {
            if !choices.iter().any(|c| c == instance) {
                errors.push(format!("{path}: {instance} not in enum {choices:?}"));
            }
        }

        if let Some(ty) = schema.get("type") {
            let ok = match ty {
                Value::String(s) => type_matches(s, instance),
                Value::Array(alts) => alts
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|s| type_matches(s, instance)),
                _ => true,
            };
            if !ok {
                errors.push(format!("{path}: type mismatch, want {ty}, got {instance}"));
            }
        }

        // Object-shape keywords only apply when the instance is actually an
        // object (a `["object","null"]` field carrying null skips these).
        if let Value::Object(map) = instance {
            if let Some(Value::Array(required)) = schema.get("required") {
                for key in required.iter().filter_map(Value::as_str) {
                    if !map.contains_key(key) {
                        errors.push(format!("{path}: missing required property '{key}'"));
                    }
                }
            }

            let props = schema.get("properties").and_then(Value::as_object);
            if let Some(props) = props {
                for (key, sub) in props {
                    if let Some(child) = map.get(key) {
                        validate_at(sub, child, root, &format!("{path}.{key}"), errors);
                    }
                }
            }

            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in map.keys() {
                    let known = props.map(|p| p.contains_key(key)).unwrap_or(false);
                    if !known {
                        errors.push(format!("{path}: unexpected property '{key}'"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::audit_export::{details, AuditEventRecord};
    use crate::services::audit_service::{AuditAction, AuditEntry, ResourceType};
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn root() -> serde_json::Value {
        schema()
    }

    fn assert_valid(instance: &serde_json::Value) {
        let s = root();
        let errors = validator::validate(&s, instance, &s);
        assert!(errors.is_empty(), "expected valid, got: {errors:?}");
    }

    fn assert_valid_against(def: &str, instance: &serde_json::Value) {
        let s = root();
        let def_schema = s["$defs"][def].clone();
        let errors = validator::validate(&def_schema, instance, &s);
        assert!(errors.is_empty(), "{def}: expected valid, got: {errors:?}");

        let emitted_keys: std::collections::BTreeSet<_> = instance
            .as_object()
            .expect("typed details serialize as an object")
            .keys()
            .cloned()
            .collect();
        let schema_keys: std::collections::BTreeSet<_> = def_schema["properties"]
            .as_object()
            .expect("typed details schema has properties")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            emitted_keys, schema_keys,
            "{def}: serialized fields and published properties drifted"
        );
    }

    // ── the committed file itself ───────────────────────────────────────

    #[test]
    fn test_committed_schema_is_valid_json_and_self_consistent() {
        let s = root();
        assert_eq!(s["properties"]["schema_version"]["const"], json!(1));
        assert_eq!(s["properties"]["category"]["const"], json!("audit"));
        assert_eq!(s["additionalProperties"], json!(true));
        // Stable outcome values are closed; actor types are open for additive
        // compatibility and publish their current values as examples.
        assert_eq!(
            s["$defs"]["Outcome"]["enum"],
            json!(["success", "failure", "denied"])
        );
        assert_eq!(
            s["$defs"]["ActorType"]["examples"],
            json!(["system", "user", "anonymous", "service_account"])
        );
        // All typed detail defs are published.
        for def in [
            "TruncatedDetails",
            "RepositoryDetails",
            "PermissionDetails",
            "TokenDetails",
            "AuthDetails",
            "ArtifactDetails",
            "SettingDetails",
        ] {
            assert!(s["$defs"][def].is_object(), "missing $def {def}");
        }
    }

    // ── live envelope records validate ──────────────────────────────────

    #[test]
    fn test_representative_envelopes_validate() {
        let uid = Uuid::new_v4();
        let published_keys: std::collections::BTreeSet<_> = root()["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let entries = vec![
            AuditEntry::new(AuditAction::Login, ResourceType::User)
                .user(uid)
                .actor_name("alice")
                .ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            AuditEntry::new(AuditAction::LoginFailed, ResourceType::User)
                .details_typed(details::AuthDetails::failed_login(Some("attacker"), None)),
            AuditEntry::new(AuditAction::ScanReaped, ResourceType::ScanResult)
                .system_actor("system:stuck_scan_janitor"),
            AuditEntry::new(AuditAction::PermissionDenied, ResourceType::User)
                .user(uid)
                .details_typed(details::AuthDetails::permission_denied(
                    "/api/v1/admin",
                    "GET",
                    "admin_privileges_required",
                )),
            AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
                .user(uid)
                .resource(Uuid::new_v4())
                .resource_name("maven-releases")
                .details_typed(details::RepositoryDetails {
                    actor_id: uid,
                    key: "maven-releases".into(),
                    is_public: false,
                    format: Some("maven".into()),
                    visibility: Some("private".into()),
                    age_gate_enabled: None,
                    age_gate_min_age_days: None,
                    age_gate_mode: None,
                }),
        ];
        for entry in &entries {
            let v = serde_json::to_value(AuditEventRecord::from_entry(entry)).unwrap();
            assert_valid(&v);
            let emitted_keys: std::collections::BTreeSet<_> =
                v.as_object().unwrap().keys().cloned().collect();
            assert_eq!(
                emitted_keys, published_keys,
                "envelope fields and published properties drifted"
            );
        }
    }

    #[test]
    fn test_envelope_with_typed_details_validates() {
        let entry = AuditEntry::new(AuditAction::ApiTokenCreated, ResourceType::ApiToken)
            .user(Uuid::new_v4())
            .details_typed(details::TokenDetails::new(
                Uuid::new_v4(),
                Some("ci"),
                "profile",
            ));
        let v = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        assert_valid(&v);
    }

    #[test]
    fn test_action_discriminator_rejects_wrong_representative_details() {
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .details(serde_json::json!({
                "key": "maven-releases",
                "is_public": false,
            }));
        let instance = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        let s = root();
        let errors = validator::validate(&s, &instance, &s);
        assert!(
            errors.iter().any(|error| error.contains("anyOf")),
            "repository action must be checked against RepositoryDetails: {errors:?}"
        );
    }

    #[test]
    fn test_action_discriminator_accepts_bounded_truncation_marker() {
        let entry = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository)
            .details(serde_json::json!({"value": "x".repeat(70_000)}));
        let instance = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        assert_eq!(instance["details"]["details_truncated"], true);
        assert_valid(&instance);
    }

    // ── typed detail structs validate against their $defs ───────────────

    #[test]
    fn test_typed_details_validate_against_defs() {
        assert_valid_against(
            "RepositoryDetails",
            &serde_json::to_value(details::RepositoryDetails {
                actor_id: Uuid::new_v4(),
                key: "maven-releases".into(),
                is_public: false,
                format: Some("maven".into()),
                visibility: Some("private".into()),
                age_gate_enabled: Some(true),
                age_gate_min_age_days: Some(14),
                age_gate_mode: None,
            })
            .unwrap(),
        );
        assert_valid_against(
            "PermissionDetails",
            &serde_json::to_value(details::PermissionDetails {
                actor_id: Uuid::new_v4(),
                role_id: Uuid::new_v4(),
                grantee_id: Uuid::new_v4(),
                repository_id: Some(Uuid::new_v4()),
            })
            .unwrap(),
        );
        assert_valid_against(
            "TokenDetails",
            &serde_json::to_value(details::TokenDetails::new(
                Uuid::new_v4(),
                Some("ci"),
                "profile",
            ))
            .unwrap(),
        );
        assert_valid_against(
            "AuthDetails",
            &serde_json::to_value(details::AuthDetails {
                username: Some("attacker".into()),
                path: Some("/api/v1/admin".into()),
                method: Some("GET".into()),
                reason: Some("admin_privileges_required".into()),
                provider: Some("oidc".into()),
                auth_method: Some("federated".into()),
            })
            .unwrap(),
        );
        assert_valid_against(
            "ArtifactDetails",
            &serde_json::to_value(details::ArtifactDetails {
                repository_id: Uuid::new_v4(),
                path: "pkg-1.2.3.tgz".into(),
                name: "pkg-1.2.3.tgz".into(),
                version: Some("1.2.3".into()),
                size_bytes: Some(4096),
                digest: Some("sha256:abcd".into()),
                uploaded_by: Some(Uuid::new_v4()),
            })
            .unwrap(),
        );
        assert_valid_against(
            "SettingDetails",
            &serde_json::to_value(details::SettingDetails {
                key: "auth.session_ttl".into(),
                old_value: Some("3600".into()),
                new_value: Some("1800".into()),
            })
            .unwrap(),
        );
    }

    // ── the validator actually rejects (guards the gate itself) ─────────

    #[test]
    fn test_schema_allows_additive_top_level_field() {
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let mut v = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("rogue".into(), json!("x"));
        let s = root();
        let errors = validator::validate(&s, &v, &s);
        assert!(
            errors.is_empty(),
            "additive fields are v1-compatible: {errors:?}"
        );
    }

    #[test]
    fn test_validator_rejects_bad_outcome_enum() {
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let mut v = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        v["outcome"] = json!("bogus");
        let s = root();
        let errors = validator::validate(&s, &v, &s);
        assert!(
            errors.iter().any(|e| e.contains("outcome")),
            "outcome enum must be enforced; got {errors:?}"
        );
    }

    #[test]
    fn test_validator_rejects_missing_required_field() {
        let entry = AuditEntry::new(AuditAction::Login, ResourceType::User);
        let mut v = serde_json::to_value(AuditEventRecord::from_entry(&entry)).unwrap();
        v.as_object_mut().unwrap().remove("correlation_id");
        let s = root();
        let errors = validator::validate(&s, &v, &s);
        assert!(
            errors.iter().any(|e| e.contains("correlation_id")),
            "required fields must be enforced; got {errors:?}"
        );
    }
}
