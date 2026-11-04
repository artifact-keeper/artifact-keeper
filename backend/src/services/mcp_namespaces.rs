//! Namespace-conditioned MCP publish grants (#5253, Phase 3).
//!
//! A permission rule may carry `conditions.mcp_namespaces`: a list of name
//! patterns. On an MCP write (publish, status change, edit, delete) such a
//! rule applies only when the server name matches one of its patterns, so
//! `{"actions": ["write"], "conditions": {"mcp_namespaces": ["com.acme/*"]}}`
//! lets its principal publish `com.acme/...` and nothing else. A pattern
//! without `/` names a namespace and its servers (`com.acme` = `com.acme/*`);
//! `*` matches any run of characters; matching is ASCII case-insensitive.
//!
//! Patterns may interpolate claims of the CI OIDC assertion the calling
//! token was exchanged for: `io.github.{repository_owner}/*`. A claim value
//! is substituted only when it is a plain label (`[A-Za-z0-9._-]`, so it can
//! never widen the pattern); a missing or unusable claim, or a credential
//! that was not minted by a CI exchange, makes that pattern match nothing.
//!
//! Claims are bound to their issuer: a rule whose patterns interpolate
//! claims must name `conditions.mcp_namespace_issuer`, and its claims are
//! taken only from a session whose verified assertion came from that issuer
//! (`iss`), so another CI provider's `repository_owner` cannot satisfy a
//! pattern written for GitHub's.
//!
//! With the repository setting `mcp_require_namespace_grant` the plain
//! repository `write` is no longer enough: only an instance administrator or
//! a matching namespace-conditioned rule may write. Without it, a matching
//! namespace rule counts as an applicable rule exactly like an IP-conditioned
//! one does in [`PermissionService::check_repository_action`]
//! (`crate::services::permission_service`), and a non-matching one is not
//! applicable to that request.

use std::collections::{BTreeSet, HashMap};

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// The condition key on `permissions.conditions`.
pub const CONDITION_KEY: &str = "mcp_namespaces";
/// The issuer condition key: the `iss` interpolated claims must come from.
pub const ISSUER_KEY: &str = "mcp_namespace_issuer";

/// An issuer URL in comparable form (trailing `/` dropped).
pub fn normalize_issuer(iss: &str) -> &str {
    iss.trim().trim_end_matches('/')
}

/// Validate the issuer condition against the rule's patterns: required when
/// any pattern interpolates a claim, refused without `mcp_namespaces`.
pub fn validate_issuer(patterns: Option<&[String]>, issuer: Option<&str>) -> Result<()> {
    match (patterns, issuer) {
        (None, Some(_)) => Err(AppError::Validation(format!(
            "conditions.{ISSUER_KEY} only applies together with conditions.{CONDITION_KEY}"
        ))),
        (Some(ps), None) if needs_claims(ps) => Err(AppError::Validation(format!(
            "conditions.{CONDITION_KEY} interpolates CI claims: name the issuer they must come \
             from in conditions.{ISSUER_KEY} (e.g. https://token.actions.githubusercontent.com)"
        ))),
        (_, Some(i)) => {
            let i = normalize_issuer(i);
            let ok = (i.starts_with("https://") || i.starts_with("http://"))
                && i.len() <= 512
                && !i.chars().any(char::is_whitespace);
            if ok {
                Ok(())
            } else {
                Err(AppError::Validation(format!(
                    "conditions.{ISSUER_KEY} must be an http(s) issuer URL of at most 512 \
                     characters"
                )))
            }
        }
        _ => Ok(()),
    }
}
pub const MAX_PATTERNS: usize = 64;
pub const MAX_PATTERN_LEN: usize = 200;
/// Claims kept per CI session, and their size limits.
const MAX_SESSION_CLAIMS: usize = 64;
const MAX_CLAIM_VALUE_LEN: usize = 256;

// ---------------------------------------------------------------------------
// Patterns (pure)
// ---------------------------------------------------------------------------

fn is_claim_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// Validate `mcp_namespaces` for a permission write: 1..=64 patterns of
/// `[A-Za-z0-9._/*-]` and `{claim}` placeholders, at most one `/`.
pub fn validate_patterns(patterns: &[String]) -> Result<()> {
    let bad = |p: &str, why: &str| {
        AppError::Validation(format!("conditions.{CONDITION_KEY}: `{p}` {why}"))
    };
    if patterns.is_empty() {
        return Err(AppError::Validation(format!(
            "conditions.{CONDITION_KEY} must name at least one namespace pattern"
        )));
    }
    if patterns.len() > MAX_PATTERNS {
        return Err(AppError::Validation(format!(
            "conditions.{CONDITION_KEY} accepts at most {MAX_PATTERNS} patterns"
        )));
    }
    for p in patterns {
        if p.is_empty() || p.len() > MAX_PATTERN_LEN {
            return Err(bad(p, "must be 1 to 200 characters"));
        }
        if p.matches('/').count() > 1 {
            return Err(bad(p, "may contain at most one `/`"));
        }
        let mut rest = p.as_str();
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('{') {
                let (claim, tail) = after
                    .split_once('}')
                    .ok_or_else(|| bad(p, "has an unclosed `{`"))?;
                if !is_claim_name(claim) {
                    return Err(bad(
                        p,
                        "names an invalid claim (lowercase letters, digits, `_`)",
                    ));
                }
                rest = tail;
            } else {
                let c = rest.chars().next().unwrap_or_default();
                if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '*')) {
                    return Err(bad(
                        p,
                        "may contain letters, digits, `.`, `_`, `-`, `/`, `*` and `{claim}`",
                    ));
                }
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    Ok(())
}

/// A claim value usable in a pattern: a plain label that cannot widen it.
fn usable_claim(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_CLAIM_VALUE_LEN
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `pattern` with every `{claim}` substituted from `claims`, or `None` when a
/// claim is absent or not a plain label.
pub fn interpolate(pattern: &str, claims: &HashMap<String, String>) -> Option<String> {
    let mut out = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let (claim, tail) = rest[start + 1..].split_once('}')?;
        let value = claims.get(claim).filter(|v| usable_claim(v))?;
        out.push_str(value);
        rest = tail;
    }
    out.push_str(rest);
    Some(out)
}

/// Whether `pattern` (after interpolation) admits server `name`.
pub fn pattern_matches(pattern: &str, name: &str, claims: &HashMap<String, String>) -> bool {
    let Some(p) = interpolate(pattern, claims) else {
        return false;
    };
    let p = if p.contains('/') { p } else { format!("{p}/*") };
    crate::services::mcp_settings::glob_matches(&p, name)
}

/// Whether any pattern needs CI claims.
pub fn needs_claims(patterns: &[String]) -> bool {
    patterns.iter().any(|p| p.contains('{'))
}

/// One applicable permission rule naming the caller on the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleGrant {
    pub actions: Vec<String>,
    /// `conditions.mcp_namespaces`, when the rule carries it.
    pub namespaces: Option<Vec<String>>,
    /// `conditions.mcp_namespace_issuer`: the only issuer whose session
    /// claims this rule's patterns interpolate.
    pub issuer: Option<String>,
}

/// The claims a rule may interpolate: the session's, when the session's
/// verified issuer is the rule's; none otherwise (pure).
fn claims_for<'c>(
    rule: &RuleGrant,
    claims: &'c HashMap<String, String>,
    empty: &'c HashMap<String, String>,
) -> &'c HashMap<String, String> {
    let bound = match (rule.issuer.as_deref(), claims.get("iss")) {
        (Some(want), Some(got)) => normalize_issuer(want) == normalize_issuer(got),
        _ => false,
    };
    if bound {
        claims
    } else {
        empty
    }
}

/// What a namespace-aware MCP write decision found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceDecision {
    /// A namespace-conditioned rule matching the name grants the action.
    NamespaceGrant,
    /// The plain repository grant (rules without the condition, or the role
    /// fallback) allows it; refused when the repository requires a grant.
    PlainWrite,
    Denied,
}

/// The permission-rule action that implies every other action. This is a
/// repository permission action, not an API-token scope.
const GRANT_ADMIN: &str = "admin";

/// Whether a permission rule's (or role's) `actions` grant `action`.
fn grants_action(acts: &[String], action: &str) -> bool {
    acts.iter().any(|a| a == action || a == GRANT_ADMIN)
}

/// The decision over the caller's applicable rules and role permissions
/// (pure). Mirrors `check_repository_action`: a role carrying `admin` always
/// wins the plain arm; applicable rules are authoritative for the principal,
/// else the role assignments decide. A namespace rule whose patterns do not
/// match `name` is not applicable to this write.
pub fn decide(
    rules: &[RuleGrant],
    role_permissions: &[Vec<String>],
    action: &str,
    name: &str,
    claims: &HashMap<String, String>,
) -> NamespaceDecision {
    let grants = |acts: &[String]| grants_action(acts, action);
    let empty = HashMap::new();
    let applicable: Vec<&RuleGrant> = rules
        .iter()
        .filter(|r| match &r.namespaces {
            None => true,
            Some(ps) => {
                let claims = claims_for(r, claims, &empty);
                ps.iter().any(|p| pattern_matches(p, name, claims))
            }
        })
        .collect();
    if applicable
        .iter()
        .any(|r| r.namespaces.is_some() && grants(&r.actions))
    {
        return NamespaceDecision::NamespaceGrant;
    }
    let role_admin = role_permissions
        .iter()
        .any(|p| p.contains(&GRANT_ADMIN.to_string()));
    let plain = role_admin
        || if applicable.is_empty() {
            role_permissions.iter().any(|p| grants(p))
        } else {
            applicable.iter().any(|r| grants(&r.actions))
        };
    if plain {
        NamespaceDecision::PlainWrite
    } else {
        NamespaceDecision::Denied
    }
}

/// Whether a write is allowed: an instance administrator always; otherwise
/// a namespace grant, or the plain grant when the repository does not
/// require a namespace grant.
pub fn allowed(is_admin: bool, decision: NamespaceDecision, require_grant: bool) -> bool {
    is_admin
        || match decision {
            NamespaceDecision::NamespaceGrant => true,
            NamespaceDecision::PlainWrite => !require_grant,
            NamespaceDecision::Denied => false,
        }
}

/// `mcp_namespaces` of a stored `conditions` document.
pub fn namespaces_of(conditions: &serde_json::Value) -> Option<Vec<String>> {
    conditions
        .get(CONDITION_KEY)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Patterns a permission write added and removed (pure). A rule that gains
/// or loses its last pattern counts every pattern.
pub fn pattern_changes(
    before: Option<&[String]>,
    after: Option<&[String]>,
) -> (Vec<String>, Vec<String>) {
    let b: BTreeSet<&String> = before.unwrap_or_default().iter().collect();
    let a: BTreeSet<&String> = after.unwrap_or_default().iter().collect();
    (
        a.difference(&b).map(|s| s.to_string()).collect(),
        b.difference(&a).map(|s| s.to_string()).collect(),
    )
}

// ---------------------------------------------------------------------------
// CI sessions: the claims behind a CI-exchanged token
// ---------------------------------------------------------------------------

fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The string-valued top-level claims of a verified assertion, bounded.
pub fn session_claims_of(claims: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            if out.len() >= MAX_SESSION_CLAIMS {
                break;
            }
            if let Some(s) = v.as_str().filter(|s| s.len() <= MAX_CLAIM_VALUE_LEN) {
                if is_claim_name(k) {
                    out.insert(k.clone(), s.into());
                }
            }
        }
    }
    serde_json::Value::Object(out)
}

/// Record the claims of a CI exchange under the minted token's digest
/// (`mcp_ci_sessions`), until the token expires. Best-effort: a failure is
/// logged and leaves the token without interpolated grants (fail closed).
pub async fn record_ci_session(
    db: &PgPool,
    access_token: &str,
    user_id: Uuid,
    claims: &serde_json::Value,
    expires_in: u64,
) {
    let res = sqlx::query(
        "WITH gone AS (DELETE FROM mcp_ci_sessions WHERE expires_at < NOW()) \
         INSERT INTO mcp_ci_sessions (token_sha256, user_id, claims, expires_at) \
         VALUES ($1, $2, $3, NOW() + make_interval(secs => $4)) \
         ON CONFLICT (token_sha256) DO NOTHING",
    )
    .bind(token_digest(access_token))
    .bind(user_id)
    .bind(session_claims_of(claims))
    .bind(expires_in as f64)
    .execute(db)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, user_id = %user_id, "could not record CI session claims");
    }
}

/// The claims recorded for `bearer` (presented by `user_id`), if the token
/// came from a CI exchange and has not expired.
pub async fn session_claims(
    db: &PgPool,
    user_id: Uuid,
    bearer: &str,
) -> Result<HashMap<String, String>> {
    let claims: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT claims FROM mcp_ci_sessions WHERE token_sha256 = $1 AND user_id = $2 \
         AND expires_at > NOW()",
    )
    .bind(token_digest(bearer))
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(claims
        .and_then(|c| serde_json::from_value(c).ok())
        .unwrap_or_default())
}

/// The bearer token of a request, if any.
pub fn bearer_of(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

// ---------------------------------------------------------------------------
// The write gate
// ---------------------------------------------------------------------------

async fn applicable_rules(db: &PgPool, user_id: Uuid, repo_id: Uuid) -> Result<Vec<RuleGrant>> {
    let query = format!(
        "SELECT p.actions, p.conditions FROM permissions p \
         WHERE ((p.principal_type IN ('user', 'service_account') AND p.principal_id = $1) \
                OR (p.principal_type = 'group' AND p.principal_id IN \
                    (SELECT group_id FROM user_group_members WHERE user_id = $1))) \
           AND ((p.target_type = 'repository' AND p.target_id = $2) \
                OR (p.target_type = 'project' AND p.target_id = \
                    (SELECT project_id FROM repositories WHERE id = $2))) \
           {}",
        crate::services::permission_service::cidr_condition_sql("p", "$3::text")
    );
    let client_ip = crate::api::middleware::client_ip::current_verified_client_ip();
    let rows: Vec<(Vec<String>, serde_json::Value)> = sqlx::query_as(sqlx::AssertSqlSafe(query))
        .bind(user_id)
        .bind(repo_id)
        .bind(client_ip.map(|ip| ip.to_string()))
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(rows
        .into_iter()
        .map(|(actions, conditions)| RuleGrant {
            actions,
            namespaces: namespaces_of(&conditions),
            issuer: conditions
                .get(ISSUER_KEY)
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
        .collect())
}

async fn role_permissions(db: &PgPool, user_id: Uuid, repo_id: Uuid) -> Result<Vec<Vec<String>>> {
    sqlx::query_scalar(
        "SELECT r.permissions FROM role_assignments ra JOIN roles r ON r.id = ra.role_id \
         WHERE ra.user_id = $1 AND (ra.repository_id = $2 OR ra.repository_id IS NULL)",
    )
    .bind(user_id)
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

async fn requires_grant(db: &PgPool, repo_id: Uuid) -> Result<bool> {
    let v: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(crate::services::mcp_settings::REQUIRE_NAMESPACE_GRANT_KEY)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(v.as_deref() == Some("true"))
}

/// The MCP write gate on top of the route's repository-level check: may
/// `auth` perform `action` (`write`, `delete`) on server `name` in
/// `repo_id`? `bearer` is the presented token (for CI claims). Every MCP
/// write handler calls this once the server name is known.
pub async fn authorize_write(
    db: &PgPool,
    auth: &crate::api::middleware::auth::AuthExtension,
    repo_id: Uuid,
    name: &str,
    action: &str,
    bearer: Option<&str>,
) -> Result<bool> {
    if auth.is_admin {
        return Ok(true);
    }
    let rules = applicable_rules(db, auth.user_id, repo_id).await?;
    let wants_claims = rules
        .iter()
        .any(|r| r.namespaces.as_deref().is_some_and(needs_claims));
    let claims = match bearer {
        Some(token) if wants_claims => session_claims(db, auth.user_id, token).await?,
        _ => HashMap::new(),
    };
    let roles = role_permissions(db, auth.user_id, repo_id).await?;
    let decision = decide(&rules, &roles, action, name, &claims);
    Ok(allowed(false, decision, requires_grant(db, repo_id).await?))
}

// ---------------------------------------------------------------------------
// Audit of grant changes
// ---------------------------------------------------------------------------

/// `MCP_NAMESPACE_GRANTED` / `MCP_NAMESPACE_REVOKED` for a permission write
/// that changed a rule's `mcp_namespaces`. `before`/`after` are the rule
/// snapshots the permission handler audits (`None` on create/delete).
pub async fn audit_grant_change(
    db: &PgPool,
    auth: &crate::api::middleware::auth::AuthExtension,
    rule_id: Uuid,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) {
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    let ns = |s: Option<&serde_json::Value>| s.and_then(|s| namespaces_of(&s["conditions"]));
    let (b, a) = (ns(before), ns(after));
    let (added, removed) = pattern_changes(b.as_deref(), a.as_deref());
    let rule = after.or(before).cloned().unwrap_or_default();
    for (action, patterns) in [
        (AuditAction::McpNamespaceGranted, added),
        (AuditAction::McpNamespaceRevoked, removed),
    ] {
        if patterns.is_empty() {
            continue;
        }
        let mut entry = AuditEntry::for_principal(action, ResourceType::Repository, auth).details(
            serde_json::json!({
                "rule_id": rule_id,
                "principal_type": rule["principal_type"],
                "principal_id": rule["principal_id"],
                "target_type": rule["target_type"],
                "target_id": rule["target_id"],
                "actions": rule["actions"],
                "patterns": patterns,
            }),
        );
        if let Some(id) = rule["target_id"].as_str().and_then(|s| s.parse().ok()) {
            entry = entry.resource(id);
        }
        audit_fire_and_forget(db.clone(), entry).await;
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn claims(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn patterns_validate() {
        for ok in [
            "com.acme/*",
            "com.acme",
            "io.github.{repository_owner}/*",
            "*/x",
        ] {
            assert!(validate_patterns(&strs(&[ok])).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a/b/c",
            "a b",
            "io.{Owner}/*",
            "io.{owner/*",
            "io.{}/*",
            "x;y",
        ] {
            assert!(validate_patterns(&strs(&[bad])).is_err(), "{bad}");
        }
        assert!(validate_patterns(&[]).is_err());
        assert!(validate_patterns(&vec!["a".to_string(); MAX_PATTERNS + 1]).is_err());
        assert!(validate_patterns(&strs(&[&"a".repeat(MAX_PATTERN_LEN + 1)])).is_err());
    }

    #[test]
    fn interpolation_substitutes_only_plain_labels() {
        let c = claims(&[
            ("repository_owner", "Acme-Labs"),
            ("bad", "a/*"),
            ("sp", "a b"),
        ]);
        assert_eq!(
            interpolate("io.github.{repository_owner}/*", &c).as_deref(),
            Some("io.github.Acme-Labs/*")
        );
        assert_eq!(interpolate("io.{bad}/*", &c), None);
        assert_eq!(interpolate("io.{sp}/*", &c), None);
        assert_eq!(interpolate("io.{missing}/*", &c), None);
        assert_eq!(interpolate("io.{unclosed", &c), None);
        assert_eq!(interpolate("plain/x", &c).as_deref(), Some("plain/x"));
    }

    #[test]
    fn patterns_match_names_and_namespaces() {
        let c = claims(&[("repository_owner", "acme")]);
        assert!(pattern_matches(
            "io.github.{repository_owner}/*",
            "io.github.acme/tool",
            &c
        ));
        assert!(!pattern_matches(
            "io.github.{repository_owner}/*",
            "io.github.evil/tool",
            &c
        ));
        assert!(!pattern_matches(
            "io.github.{repository_owner}/*",
            "io.github.acme/x",
            &HashMap::new()
        ));
        assert!(pattern_matches("com.acme", "com.acme/x", &c));
        assert!(pattern_matches("COM.acme", "com.ACME/x", &c));
        assert!(!pattern_matches("com.acme", "com.acmecorp/x", &c));
        assert!(pattern_matches("com.acme/x", "com.acme/x", &c));
        assert!(needs_claims(&strs(&["a", "{b}/*"])));
        assert!(!needs_claims(&strs(&["a/*"])));
    }

    fn rule(actions: &[&str], ns: Option<&[&str]>) -> RuleGrant {
        RuleGrant {
            actions: strs(actions),
            namespaces: ns.map(strs),
            issuer: None,
        }
    }

    /// Review finding 14: interpolated claims count only from a session of
    /// the rule's issuer, and the issuer is required for such a rule.
    #[test]
    fn claims_are_bound_to_the_rule_issuer() {
        const GH: &str = "https://token.actions.githubusercontent.com";
        let mut r = rule(&["write"], Some(&["io.github.{repository_owner}/*"]));
        r.issuer = Some(GH.into());
        let claims = |iss: &str| {
            HashMap::from([
                ("repository_owner".to_string(), "acme".to_string()),
                ("iss".to_string(), iss.to_string()),
            ])
        };
        use NamespaceDecision::*;
        let d = |c: &HashMap<String, String>| {
            decide(
                std::slice::from_ref(&r),
                &[],
                "write",
                "io.github.acme/x",
                c,
            )
        };
        assert_eq!(d(&claims(GH)), NamespaceGrant);
        assert_eq!(d(&claims(&format!("{GH}/"))), NamespaceGrant);
        assert_eq!(d(&claims("https://gitlab.example.test")), Denied);
        let mut unbound = r.clone();
        unbound.issuer = None;
        assert_eq!(
            decide(&[unbound], &[], "write", "io.github.acme/x", &claims(GH)),
            Denied
        );
        let ps = strs(&["io.github.{repository_owner}/*"]);
        assert!(validate_issuer(Some(&ps), None).is_err());
        assert!(validate_issuer(Some(&ps), Some(GH)).is_ok());
        assert!(validate_issuer(Some(&ps), Some("not a url")).is_err());
        assert!(validate_issuer(None, Some(GH)).is_err());
        assert!(validate_issuer(Some(&strs(&["com.acme/*"])), None).is_ok());
    }

    #[test]
    fn decide_follows_the_rule_then_role_model() {
        let none = HashMap::new();
        let ns = rule(&["write"], Some(&["com.acme/*"]));
        let plain = rule(&["write"], None);
        let read = rule(&["read"], None);
        let dev = vec![strs(&["read", "write"])];
        use NamespaceDecision::*;
        assert_eq!(
            decide(std::slice::from_ref(&ns), &[], "write", "com.acme/x", &none),
            NamespaceGrant
        );
        // A non-matching namespace rule is not applicable: roles decide.
        assert_eq!(
            decide(
                std::slice::from_ref(&ns),
                &[],
                "write",
                "com.other/x",
                &none
            ),
            Denied
        );
        assert_eq!(
            decide(
                std::slice::from_ref(&ns),
                &dev,
                "write",
                "com.other/x",
                &none
            ),
            PlainWrite
        );
        assert_eq!(
            decide(&[plain], &[], "write", "com.other/x", &none),
            PlainWrite
        );
        // An applicable rule is authoritative over the role fallback.
        assert_eq!(decide(&[read], &dev, "write", "com.acme/x", &none), Denied);
        assert_eq!(
            decide(&[], &[strs(&["admin"])], "write", "a/b", &none),
            PlainWrite
        );
        assert_eq!(decide(&[], &[], "write", "a/b", &none), Denied);
        let ns_admin = rule(&["admin"], Some(&["com.acme"]));
        assert_eq!(
            decide(&[ns_admin], &[], "delete", "com.acme/x", &none),
            NamespaceGrant
        );
    }

    #[test]
    fn allowed_honours_the_repository_requirement() {
        use NamespaceDecision::*;
        assert!(allowed(false, NamespaceGrant, true));
        assert!(allowed(false, PlainWrite, false));
        assert!(!allowed(false, PlainWrite, true));
        assert!(!allowed(false, Denied, false));
        assert!(allowed(true, Denied, true));
    }

    #[test]
    fn pattern_changes_and_namespaces_of() {
        let a = strs(&["a/*", "b/*"]);
        let b = strs(&["b/*", "c/*"]);
        assert_eq!(
            pattern_changes(Some(&a), Some(&b)),
            (strs(&["c/*"]), strs(&["a/*"]))
        );
        assert_eq!(pattern_changes(None, Some(&a)), (a.clone(), vec![]));
        assert_eq!(pattern_changes(Some(&a), None), (vec![], a.clone()));
        assert_eq!(
            namespaces_of(&serde_json::json!({"mcp_namespaces": ["x/*"]})),
            Some(strs(&["x/*"]))
        );
        assert_eq!(namespaces_of(&serde_json::json!({})), None);
    }

    #[test]
    fn session_claims_keep_bounded_string_claims() {
        let c = session_claims_of(&serde_json::json!({
            "repository_owner": "acme", "exp": 5, "Weird-Key": "x",
            "long": "y".repeat(MAX_CLAIM_VALUE_LEN + 1),
        }));
        assert_eq!(c, serde_json::json!({"repository_owner": "acme"}));
        let mut h = axum::http::HeaderMap::new();
        assert_eq!(bearer_of(&h), None);
        h.insert("authorization", "Bearer abc".parse().unwrap());
        assert_eq!(bearer_of(&h), Some("abc"));
        assert_ne!(token_digest("a"), token_digest("b"));
    }

    #[tokio::test]
    async fn authorize_write_end_to_end() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        use crate::api::handlers::test_db_helpers as tdh;
        let (user, name) = tdh::create_user(&pool).await;
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "mcp").await;
        let auth = tdh::make_auth(user, &name);
        let rule =
            tdh::grant_permission(&pool, "user", user, "repository", repo, &["read", "write"])
                .await;
        sqlx::query("UPDATE permissions SET conditions = $2 WHERE id = $1")
            .bind(rule)
            .bind(
                serde_json::json!({"mcp_namespaces": ["io.github.{repository_owner}/*"],
                                     "mcp_namespace_issuer": "https://ci.example.test"}),
            )
            .execute(&pool)
            .await
            .unwrap();
        let token = format!("tok-{}", Uuid::new_v4());
        record_ci_session(
            &pool,
            &token,
            user,
            &serde_json::json!({"repository_owner": "acme", "iss": "https://ci.example.test"}),
            60,
        )
        .await;
        assert!(authorize_write(
            &pool,
            &auth,
            repo,
            "io.github.acme/x",
            "write",
            Some(&token)
        )
        .await
        .unwrap());
        assert!(!authorize_write(
            &pool,
            &auth,
            repo,
            "io.github.evil/x",
            "write",
            Some(&token)
        )
        .await
        .unwrap());
        assert!(!authorize_write(
            &pool,
            &auth,
            repo,
            "io.github.acme/x",
            "write",
            Some("other")
        )
        .await
        .unwrap());
        assert!(
            !authorize_write(&pool, &auth, repo, "io.github.acme/x", "write", None)
                .await
                .unwrap()
        );
        // A developer role plus the setting: plain write no longer suffices.
        tdh::grant_repo_access(&pool, repo, user).await;
        assert!(
            authorize_write(&pool, &auth, repo, "com.other/x", "write", None)
                .await
                .unwrap()
        );
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) \
             VALUES ($1, 'mcp_require_namespace_grant', 'true')",
        )
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !authorize_write(&pool, &auth, repo, "com.other/x", "write", None)
                .await
                .unwrap()
        );
        assert!(authorize_write(
            &pool,
            &auth,
            repo,
            "io.github.acme/x",
            "write",
            Some(&token)
        )
        .await
        .unwrap());
        assert!(authorize_write(
            &pool,
            &tdh::admin_auth(user, &name),
            repo,
            "com.other/x",
            "write",
            None
        )
        .await
        .unwrap());
        for sql in [
            "DELETE FROM permissions WHERE target_id = $1",
            "DELETE FROM repository_config WHERE repository_id = $1",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(repo)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM mcp_ci_sessions WHERE user_id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        tdh::cleanup_member_repo(&pool, repo, &dir).await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await;
    }

    /// Review finding 1: a namespace-conditioned rule grants nothing to a
    /// generic permission check (write/delete/read on the artifact API, the
    /// ACL-engagement probe); only the MCP namespace gate evaluates it.
    #[tokio::test]
    async fn namespace_rule_grants_nothing_outside_the_mcp_gate() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::permission_service::PermissionService;
        let (user, name) = tdh::create_user(&pool).await;
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "mcp").await;
        let auth = tdh::make_auth(user, &name);
        let rule = tdh::grant_permission(
            &pool,
            "user",
            user,
            "repository",
            repo,
            &["read", "write", "delete", "admin"],
        )
        .await;
        sqlx::query("UPDATE permissions SET conditions = $2 WHERE id = $1")
            .bind(rule)
            .bind(serde_json::json!({"mcp_namespaces": ["com.acme/*"]}))
            .execute(&pool)
            .await
            .unwrap();
        let perms = PermissionService::new(pool.clone());
        for action in ["read", "write", "delete", "admin"] {
            assert!(
                !perms
                    .check_repository_action(user, repo, action, false)
                    .await
                    .unwrap(),
                "{action}: a namespace rule is not a generic grant"
            );
            assert!(
                !perms
                    .check_permission(user, "repository", repo, action, false)
                    .await
                    .unwrap(),
                "{action}: resolve_actions must skip the namespace rule"
            );
        }
        assert!(
            !perms
                .has_any_rules_for_target("repository", repo)
                .await
                .unwrap(),
            "a namespace rule does not engage the generic ACL"
        );
        // The MCP surface's route-level check counts it (the handler's
        // namespace gate then decides the name); the MCP gate honours it.
        assert!(perms
            .check_mcp_surface_action(user, repo, "write", false)
            .await
            .unwrap());
        assert!(!perms
            .check_mcp_surface_action(Uuid::new_v4(), repo, "write", false)
            .await
            .unwrap());
        assert!(
            authorize_write(&pool, &auth, repo, "com.acme/x", "write", None)
                .await
                .unwrap()
        );
        assert!(
            !authorize_write(&pool, &auth, repo, "com.other/x", "write", None)
                .await
                .unwrap()
        );
        // The role fallback is unaffected by the (non-applicable) rule.
        tdh::grant_repo_access(&pool, repo, user).await;
        let perms = PermissionService::new(pool.clone());
        assert!(perms
            .check_repository_action(user, repo, "write", false)
            .await
            .unwrap());
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
        tdh::cleanup_member_repo(&pool, repo, &dir).await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await;
    }
}
