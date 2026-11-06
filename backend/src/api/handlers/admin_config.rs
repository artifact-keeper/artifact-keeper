//! Config-as-code export and import (#5292): the instance's repositories and
//! their per-repository settings as one versioned JSON document.
//!
//! Every read goes through the handler behind the matching per-setting GET
//! route and every write through the handler behind the matching PUT/PATCH,
//! called with the admin's own principal. The document therefore cannot drift
//! from the API, and an import gets the normal validation, SSRF checks, cache
//! invalidation and per-repository audit rows. The document types, the diff
//! and the request bodies live in [`crate::services::config_document`].

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::api::extractors::Json;
use crate::api::handlers::repositories as repos;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::config_document::{
    self as doc, ConfigAwsUpstreamAuth, ConfigDocument, ConfigEgressProxy, ConfigNpmScopePolicy,
    ConfigPlan, ConfigPlanUpdate, ConfigRepository, ConfigSecretRef, ConfigUpstreamAuth,
    ConfigVirtualMember,
};
use crate::services::repository_service::{RepoVisibility, RepositoryService};
use crate::services::upstream_filter::UpstreamFilter;

/// Routes nested at `/api/v1/admin/config` (behind `admin_middleware`).
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/export", get(export_config))
        .route("/import", post(import_config))
}

#[derive(OpenApi)]
#[openapi(
    paths(export_config, import_config),
    components(schemas(
        ConfigDocument,
        ConfigRepository,
        ConfigSecretRef,
        ConfigVirtualMember,
        ConfigEgressProxy,
        ConfigUpstreamAuth,
        ConfigAwsUpstreamAuth,
        ConfigNpmScopePolicy,
        ConfigPlan,
        ConfigPlanUpdate,
        ConfigImportRequest,
        ConfigImportMode,
    ))
)]
pub struct AdminConfigApiDoc;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ConfigExportQuery {
    /// Comma-separated repository keys to export. Omit for every repository.
    pub repositories: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConfigImportMode {
    /// Report what an apply would change; write nothing.
    Plan,
    /// Create missing repositories and update changed settings.
    Apply,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ConfigImportQuery {
    pub mode: ConfigImportMode,
    /// Delete target repositories the document does not mention. Only
    /// `false` is accepted in this version.
    #[serde(default)]
    pub prune: bool,
}

/// Import body. A bare document (no `document` key) is accepted too, with
/// no secrets. Deliberately not `Debug`: `secrets` holds credentials.
#[derive(Deserialize, ToSchema)]
pub struct ConfigImportRequest {
    #[schema(value_type = ConfigDocument)]
    pub document: serde_json::Value,
    /// Values for the document's `secret_ref` placeholders, by name
    /// (`upstream_auth/<key>`: password or token; `upstream_url/<key>` and
    /// `egress_proxy/<key>`: percent-encoded `user:password` userinfo).
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

fn split_import_body(body: serde_json::Value) -> Result<ConfigImportRequest> {
    if body.get("document").is_some() {
        serde_json::from_value(body)
            .map_err(|e| AppError::Validation(format!("invalid import request: {e}")))
    } else {
        Ok(ConfigImportRequest {
            document: body,
            secrets: BTreeMap::new(),
        })
    }
}

fn parse_key_list(list: &str) -> Vec<String> {
    let keys: BTreeSet<String> = list
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .collect();
    keys.into_iter().collect()
}

/// Every repository key on the instance, sorted.
async fn all_repository_keys(state: &SharedState) -> Result<BTreeSet<String>> {
    let (repositories, _) = RepositoryService::new(state.db.clone())
        .list(0, i64::MAX, None, None, RepoVisibility::All, None, None)
        .await?;
    Ok(repositories.into_iter().map(|r| r.key).collect())
}

/// Read one repository into its document form through the GET handlers.
async fn export_repository(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<ConfigRepository> {
    let st = || State(state.clone());
    let ext = || Extension(Some(auth.clone()));
    let path = || Path(key.to_string());

    let Json(repo) = repos::get_repository(st(), ext(), path()).await?;
    let (upstream_url, upstream_url_credentials) =
        doc::upstream_url_fields(key, repo.upstream_url, repo.upstream_url_has_credentials);
    let Json(routing) = repos::get_routing_rules(st(), ext(), path()).await?;
    let mut out = ConfigRepository {
        key: repo.key,
        name: repo.name,
        description: repo.description,
        format: repo.format,
        format_key: repo.format_key,
        repo_type: repo.repo_type,
        visibility: repo.visibility,
        upstream_url,
        upstream_url_credentials,
        allow_public_with_upstream_credentials: repo.allow_public_with_upstream_credentials,
        quota_bytes: repo.quota_bytes,
        promotion_only: repo.promotion_only,
        versioning_enabled: repo.versioning_enabled,
        custom_user_agent: repo.custom_user_agent,
        curation_enabled: repo.curation_enabled,
        curation_default_action: repo.curation_default_action,
        members: Vec::new(),
        upstream_mode: None,
        cache_ttl_seconds: None,
        on_upstream_not_found: None,
        stale_if_error_grace_seconds: None,
        upstream_filter: None,
        routing_rules: routing.rules,
        egress_proxy: None,
        upstream_auth: None,
        npm_scope_policy: None,
    };

    match out.repo_type.as_str() {
        "remote" => {
            // The stored mode, not the effective one: the instance-wide
            // `PROXY_UPSTREAM_MODE` override belongs to the target instance.
            let Json(mode) = repos::get_upstream_mode(st(), ext(), path()).await?;
            out.upstream_mode = doc::upstream_mode_from_read(mode.upstream_mode);
            let Json(ttl) = repos::get_cache_ttl(st(), ext(), path()).await?;
            out.cache_ttl_seconds = Some(ttl.cache_ttl_seconds);
            let Json(nf) = repos::get_on_upstream_not_found(st(), ext(), path()).await?;
            out.on_upstream_not_found = Some(nf.on_upstream_not_found);
            let Json(grace) = repos::get_stale_if_error_grace(st(), ext(), path()).await?;
            out.stale_if_error_grace_seconds = grace.override_seconds;
            let Json(filter) = repos::get_upstream_filter(st(), ext(), path()).await?;
            if let Some(err) = filter.error {
                // Exporting it as "no filter" would fail open on import.
                return Err(AppError::Internal(format!(
                    "repository {key}: the stored upstream filter is unusable ({err}); fix it before exporting"
                )));
            }
            out.upstream_filter = filter.active.then_some(UpstreamFilter {
                include_patterns: filter.include_patterns,
                exclude_patterns: filter.exclude_patterns,
            });
            let Json(egress) = repos::get_egress_proxy(st(), ext(), path()).await?;
            out.egress_proxy = doc::egress_proxy_from_read(
                key,
                &egress.mode,
                egress.proxy_url.as_deref(),
                egress.no_proxy,
                egress.proxy_credentials_configured,
            );
            // No GET route exists for upstream auth; these are the reads
            // `get_repository` and `set_upstream_auth` make.
            let repo_id = repo.id;
            let auth_type =
                crate::services::upstream_auth::get_upstream_auth_type(&state.db, repo_id).await?;
            let stored =
                crate::services::upstream_auth::stored_credentials_json(&state.db, repo_id).await?;
            out.upstream_auth =
                doc::upstream_auth_from_stored(key, auth_type.as_deref(), stored.as_deref());
            if out.format == "npm" {
                let Json(policy) = repos::get_npm_scope_policy(st(), ext(), path()).await?;
                out.npm_scope_policy = policy.active.then_some(ConfigNpmScopePolicy {
                    allowed_scopes: policy.allowed_scopes,
                    allow_unscoped: policy.allow_unscoped,
                });
            }
        }
        "virtual" => {
            let (members, _) = repos::visible_virtual_members(state, auth, key).await?;
            out.members = members
                .into_iter()
                .map(|m| ConfigVirtualMember {
                    key: m.member_repo_key,
                    priority: m.priority,
                })
                .collect();
            doc::sort_members(&mut out.members);
        }
        _ => {}
    }
    Ok(out)
}

/// Export instance configuration as one document
///
/// Repositories (keyed by `key`, sorted) with their per-repository settings.
/// Credentials are never included: each appears as a `{"secret_ref": ...}`
/// placeholder an import must be given. See `docs/config-as-code.md`.
#[utoipa::path(
    get,
    path = "/export",
    context_path = "/api/v1/admin/config",
    tag = "admin",
    params(ConfigExportQuery),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Config document", body = ConfigDocument),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "A requested repository does not exist"),
    )
)]
pub async fn export_config(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ConfigExportQuery>,
) -> Result<Json<ConfigDocument>> {
    let keys = match query.repositories.as_deref() {
        Some(list) => parse_key_list(list),
        None => all_repository_keys(&state).await?.into_iter().collect(),
    };
    let mut repositories = Vec::with_capacity(keys.len());
    for key in &keys {
        repositories.push(export_repository(&state, &auth, key).await?);
    }
    Ok(Json(doc::document(repositories)))
}

/// What an apply wrote, for the `CONFIG_IMPORTED` row.
#[derive(Default)]
struct ApplyProgress {
    created: Vec<String>,
    updated: Vec<String>,
    members_updated: Vec<String>,
}

/// Turn a body built by `config_document` into the handler's request type.
fn parse<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|e| AppError::Internal(format!("import body: {e}")))
}

/// Write the changed settings of one repository through the PUT/PATCH handlers.
async fn apply_settings(
    state: &SharedState,
    auth: &AuthExtension,
    desired: &ConfigRepository,
    changes: &BTreeSet<String>,
    secrets: &BTreeMap<String, String>,
) -> Result<()> {
    let st = || State(state.clone());
    let ext = || Extension(Some(auth.clone()));
    let path = || Path(desired.key.clone());
    let changed = |f: &str| changes.contains(f);

    if let Some(patch) = doc::patch_body(desired, changes, secrets)? {
        repos::update_repository(st(), ext(), path(), Json(parse(patch)?)).await?;
    }
    if changed("upstream_auth") {
        let body = doc::upstream_auth_body(desired, secrets)?;
        repos::set_upstream_auth(st(), ext(), path(), Json(parse(body)?)).await?;
    }
    if changed("egress_proxy") {
        let (mode, proxy_url, no_proxy) = doc::egress_proxy_body(desired, secrets)?;
        let body = repos::EgressProxyRequest {
            mode,
            proxy_url,
            no_proxy,
        };
        repos::set_egress_proxy(st(), ext(), path(), Json(body)).await?;
    }
    if changed("upstream_mode") {
        let body = repos::SetUpstreamModeRequest {
            upstream_mode: doc::upstream_mode_body(desired),
        };
        repos::set_upstream_mode(st(), ext(), path(), Json(body)).await?;
    }
    if let (true, Some(cache_ttl_seconds)) =
        (changed("cache_ttl_seconds"), desired.cache_ttl_seconds)
    {
        let body = repos::SetCacheTtlRequest { cache_ttl_seconds };
        repos::set_cache_ttl(st(), ext(), path(), Json(body)).await?;
    }
    if let (true, Some(on_upstream_not_found)) = (
        changed("on_upstream_not_found"),
        desired.on_upstream_not_found,
    ) {
        let body = repos::SetOnUpstreamNotFoundRequest {
            on_upstream_not_found,
        };
        repos::set_on_upstream_not_found(st(), ext(), path(), Json(body)).await?;
    }
    if let (true, Some(stale_if_error_grace_seconds)) = (
        changed("stale_if_error_grace_seconds"),
        desired.stale_if_error_grace_seconds,
    ) {
        let body = repos::SetStaleIfErrorGraceRequest {
            stale_if_error_grace_seconds,
        };
        repos::set_stale_if_error_grace(st(), ext(), path(), Json(body)).await?;
    }
    if changed("upstream_filter") {
        match &desired.upstream_filter {
            Some(filter) => {
                repos::set_upstream_filter(st(), ext(), path(), Json(filter.clone())).await?;
            }
            None => {
                repos::delete_upstream_filter(st(), ext(), path()).await?;
            }
        }
    }
    if changed("routing_rules") {
        if desired.routing_rules.is_empty() {
            repos::delete_routing_rules(st(), ext(), path()).await?;
        } else {
            let body = repos::SetRoutingRulesRequest {
                rules: desired.routing_rules.clone(),
            };
            repos::set_routing_rules(st(), ext(), path(), Json(body)).await?;
        }
    }
    if changed("npm_scope_policy") {
        // Absent means unrestricted: an empty allow-list that admits
        // unscoped names is the inactive policy.
        let body = match &desired.npm_scope_policy {
            Some(p) => repos::SetNpmScopePolicyRequest {
                allowed_scopes: p.allowed_scopes.clone(),
                allow_unscoped: p.allow_unscoped,
            },
            None => repos::SetNpmScopePolicyRequest {
                allowed_scopes: Vec::new(),
                allow_unscoped: true,
            },
        };
        repos::set_npm_scope_policy(st(), ext(), path(), Json(body)).await?;
    }
    Ok(())
}

/// Replace a virtual repository's members with the document's list.
async fn apply_members(
    state: &SharedState,
    auth: &AuthExtension,
    desired: &ConfigRepository,
) -> Result<()> {
    let body = repos::UpdateVirtualMembersRequest {
        members: desired
            .members
            .iter()
            .map(|m| repos::VirtualMemberPriority {
                member_key: m.key.clone(),
                priority: m.priority,
            })
            .collect(),
    };
    repos::update_virtual_members(
        State(state.clone()),
        Extension(Some(auth.clone())),
        Path(desired.key.clone()),
        Json(body),
    )
    .await?;
    Ok(())
}

/// Apply `document` in dependency order: create and configure every
/// non-virtual repository, then the virtual ones, then virtual memberships
/// (whose members must all exist by then).
async fn apply_document(
    state: &SharedState,
    auth: &AuthExtension,
    document: &ConfigDocument,
    current: &BTreeMap<String, ConfigRepository>,
    secrets: &BTreeMap<String, String>,
    progress: &mut ApplyProgress,
) -> Result<()> {
    let mut memberships = Vec::new();
    for desired in doc::apply_order(document) {
        if !current.contains_key(&desired.key) {
            let body = doc::create_body(desired, secrets)?;
            let bytes = serde_json::to_vec(&body)
                .map_err(|e| AppError::Internal(format!("import body: {e}")))?;
            repos::create_repository(
                State(state.clone()),
                Extension(Some(auth.clone())),
                bytes.into(),
            )
            .await?;
            progress.created.push(desired.key.clone());
        }
        // Diff against a fresh read: a create sets only what the create
        // route takes, and the rest is written here.
        let now = export_repository(state, auth, &desired.key).await?;
        let mut changes: BTreeSet<String> =
            doc::changed_fields(desired, &now).into_iter().collect();
        if changes.remove("members") {
            memberships.push(desired);
        }
        if !changes.is_empty() {
            apply_settings(state, auth, desired, &changes, secrets).await?;
            if current.contains_key(&desired.key) {
                progress.updated.push(desired.key.clone());
            }
        }
    }
    for desired in memberships {
        apply_members(state, auth, desired).await?;
        progress.members_updated.push(desired.key.clone());
    }
    Ok(())
}

async fn audit_import(
    state: &SharedState,
    auth: &AuthExtension,
    plan: &ConfigPlan,
    progress: &ApplyProgress,
    error: Option<&AppError>,
) {
    let details = serde_json::json!({
        "schema_version": doc::SCHEMA_VERSION,
        "completed": error.is_none(),
        "error": error.map(|e| e.to_string()),
        "planned_create": plan.create,
        "planned_update": plan.update.iter().map(|u| &u.key).collect::<Vec<_>>(),
        "unchanged": plan.unchanged.len(),
        "not_in_document": plan.not_in_document.len(),
        "created": progress.created,
        "updated": progress.updated,
        "members_updated": progress.members_updated,
        "prune": false,
    });
    let mut entry =
        AuditEntry::for_principal(AuditAction::ConfigImported, ResourceType::Setting, auth)
            .resource_name("config_document")
            .details(details);
    if error.is_some() {
        entry = entry.outcome(crate::services::audit_export::Outcome::Failure);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;
}

/// Plan or apply a config document
///
/// `mode=plan` diffs the document against this instance and writes nothing.
/// `mode=apply` creates missing repositories and updates changed settings
/// through the regular repository routes, in dependency order, and records
/// one `CONFIG_IMPORTED` audit row. It never deletes; `prune=true` is not
/// implemented yet. A `secret_ref` whose setting must be written has to be
/// supplied in `secrets`; a plan lists any that are missing and an apply is
/// refused until they are given.
#[utoipa::path(
    post,
    path = "/import",
    context_path = "/api/v1/admin/config",
    tag = "admin",
    params(ConfigImportQuery),
    request_body = ConfigImportRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The plan, with `applied: true` after an apply", body = ConfigPlan),
        (status = 400, description = "Unsupported schema_version, invalid document, prune=true, or (apply) missing secrets / changes an import cannot make"),
        (status = 403, description = "Admin privileges required"),
    )
)]
pub async fn import_config(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ConfigImportQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<ConfigPlan>> {
    if query.prune {
        return Err(AppError::Validation(
            "prune=true is not implemented yet; imports never delete".to_string(),
        ));
    }
    let request = split_import_body(body)?;
    let document = doc::parse_document(request.document)?;
    let target_keys = all_repository_keys(&state).await?;
    let mut current = BTreeMap::new();
    for repo in &document.repositories {
        if target_keys.contains(&repo.key) && !current.contains_key(&repo.key) {
            let exported = export_repository(&state, &auth, &repo.key).await?;
            current.insert(repo.key.clone(), exported);
        }
    }
    let mut plan = doc::plan(&document, &current, &target_keys, &request.secrets);
    if query.mode == ConfigImportMode::Plan {
        return Ok(Json(plan));
    }
    if !plan.applicable {
        return Err(AppError::Validation(plan.refusal_message()));
    }
    let mut progress = ApplyProgress::default();
    let result = apply_document(
        &state,
        &auth,
        &document,
        &current,
        &request.secrets,
        &mut progress,
    )
    .await;
    audit_import(&state, &auth, &plan, &progress, result.as_ref().err()).await;
    result?;
    plan.applied = true;
    Ok(Json(plan))
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    #[test]
    fn key_list_is_trimmed_sorted_and_deduplicated() {
        assert_eq!(parse_key_list(" b,a,,b , c"), ["a", "b", "c"]);
        assert!(parse_key_list(" , ").is_empty());
    }

    #[test]
    fn import_body_accepts_a_wrapped_or_a_bare_document() {
        let wrapped = split_import_body(serde_json::json!({
            "document": { "schema_version": 1 },
            "secrets": { "upstream_auth/a": "pw" }
        }))
        .unwrap();
        assert_eq!(wrapped.document["schema_version"], 1);
        assert_eq!(wrapped.secrets["upstream_auth/a"], "pw");
        let bare = split_import_body(serde_json::json!({ "schema_version": 1 })).unwrap();
        assert!(bare.secrets.is_empty());
        assert!(split_import_body(serde_json::json!({ "document": 1, "secrets": 2 })).is_err());
    }

    /// Strip the per-export stamps so two documents compare on content.
    fn content(document: &ConfigDocument) -> serde_json::Value {
        let mut value = serde_json::to_value(document).unwrap();
        let map = value.as_object_mut().unwrap();
        map.remove("exported_at");
        map.remove("producer");
        value
    }

    async fn export_keys(state: &SharedState, auth: &AuthExtension, keys: &str) -> ConfigDocument {
        let Json(document) = export_config(
            State(state.clone()),
            Extension(auth.clone()),
            Query(ConfigExportQuery {
                repositories: Some(keys.to_string()),
            }),
        )
        .await
        .expect("export");
        document
    }

    async fn import(
        state: &SharedState,
        auth: &AuthExtension,
        mode: ConfigImportMode,
        prune: bool,
        body: serde_json::Value,
    ) -> Result<ConfigPlan> {
        import_config(
            State(state.clone()),
            Extension(auth.clone()),
            Query(ConfigImportQuery { mode, prune }),
            Json(body),
        )
        .await
        .map(|Json(plan)| plan)
    }

    async fn delete_repo_by_key(pool: &sqlx::PgPool, key: &str) {
        let id: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_optional(pool)
                .await
                .unwrap();
        if let Some(id) = id {
            for sql in [
                "DELETE FROM role_assignments WHERE repository_id = $1",
                "DELETE FROM permissions WHERE target_type = 'repository' AND target_id = $1",
                "DELETE FROM repository_config WHERE repository_id = $1",
                "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 OR member_repo_id = $1",
                "DELETE FROM repositories WHERE id = $1",
            ] {
                let _ = sqlx::query(sql).bind(id).execute(pool).await;
            }
        }
    }

    /// #5292 acceptance: export a configured Remote (and a Virtual over it),
    /// delete both, apply the document, export again: identical apart from
    /// `exported_at`/`producer`. A second apply is a no-op.
    /// The fixture credential, assembled so secret scanners do not take it for a
    /// real one.
    const CANARY_5292: &str = concat!("canary", "-", "5292");

    #[tokio::test]
    async fn export_apply_export_round_trips_and_reapply_is_a_noop() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("ak-5292-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = tdh::admin_auth(user_id, &username);
        let ext = || Extension(Some(auth.clone()));
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let remote_key = format!("cfg-5292-r-{suffix}");
        let virtual_key = format!("cfg-5292-v-{suffix}");
        let keys = format!("{remote_key},{virtual_key}");

        let create = |key: &str, extra: serde_json::Value| {
            let mut body = serde_json::json!({
                "key": key, "name": key, "format": "generic",
                "description": "round trip #5292",
            });
            if let (serde_json::Value::Object(b), serde_json::Value::Object(e)) = (&mut body, extra)
            {
                b.extend(e);
            }
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap())
        };
        repos::create_repository(
            State(state.clone()),
            ext(),
            create(
                &remote_key,
                serde_json::json!({
                    "repo_type": "remote",
                    "upstream_url": "https://upstream.example.com/api",
                }),
            ),
        )
        .await
        .expect("create remote");
        repos::create_repository(
            State(state.clone()),
            ext(),
            create(&virtual_key, serde_json::json!({ "repo_type": "virtual" })),
        )
        .await
        .expect("create virtual");
        let path = || Path(remote_key.clone());
        repos::set_cache_ttl(
            State(state.clone()),
            ext(),
            path(),
            Json(repos::SetCacheTtlRequest {
                cache_ttl_seconds: 1234,
            }),
        )
        .await
        .expect("cache ttl");
        repos::set_on_upstream_not_found(
            State(state.clone()),
            ext(),
            path(),
            Json(repos::SetOnUpstreamNotFoundRequest {
                on_upstream_not_found:
                    crate::services::upstream_not_found_policy::OnUpstreamNotFound::Keep,
            }),
        )
        .await
        .expect("on_upstream_not_found");
        repos::set_upstream_mode(
            State(state.clone()),
            ext(),
            path(),
            Json(repos::SetUpstreamModeRequest {
                upstream_mode: crate::services::upstream_mode::UpstreamMode::CacheOnly,
            }),
        )
        .await
        .expect("upstream mode");
        repos::set_upstream_filter(
            State(state.clone()),
            ext(),
            path(),
            Json(UpstreamFilter {
                include_patterns: vec!["^acme/".into()],
                exclude_patterns: vec!["\\.tmp$".into()],
            }),
        )
        .await
        .expect("upstream filter");
        repos::set_upstream_auth(
            State(state.clone()),
            ext(),
            path(),
            Json(
                serde_json::from_value(serde_json::json!({
                    "auth_type": "basic", "username": "svc", "pass\u{77}ord": CANARY_5292
                }))
                .unwrap(),
            ),
        )
        .await
        .expect("upstream auth");
        apply_members(
            &state,
            &auth,
            &serde_json::from_value(serde_json::json!({
                "key": virtual_key, "name": virtual_key, "format": "generic",
                "repo_type": "virtual", "visibility": "private",
                "members": [{ "key": remote_key, "priority": 1 }],
            }))
            .unwrap(),
        )
        .await
        .expect("members");

        let first = export_keys(&state, &auth, &keys).await;
        let text = serde_json::to_string(&first).unwrap();
        assert!(!text.contains(CANARY_5292), "secret leaked: {text}");
        let remote = &first.repositories[0];
        assert_eq!(remote.key, remote_key);
        assert_eq!(remote.cache_ttl_seconds, Some(1234));
        // #5407: the cache-only mode is exported; a Virtual has none.
        assert_eq!(
            remote.upstream_mode,
            Some(crate::services::upstream_mode::UpstreamMode::CacheOnly)
        );
        assert!(first.repositories[1].upstream_mode.is_none());
        assert!(remote.upstream_filter.is_some());
        let auth_doc = remote
            .upstream_auth
            .as_ref()
            .expect("upstream auth exported");
        assert_eq!(auth_doc.username.as_deref(), Some("svc"));
        assert_eq!(first.repositories[1].members.len(), 1);

        // Delete both, then: a plan without the secret is not applicable,
        // an apply without it is refused, and nothing was created.
        delete_repo_by_key(&pool, &virtual_key).await;
        delete_repo_by_key(&pool, &remote_key).await;
        let document = serde_json::to_value(&first).unwrap();
        let plan = import(
            &state,
            &auth,
            ConfigImportMode::Plan,
            false,
            document.clone(),
        )
        .await
        .unwrap();
        assert_eq!(plan.create.len(), 2);
        assert_eq!(
            plan.missing_secrets,
            [format!("upstream_auth/{remote_key}")]
        );
        assert!(!plan.applicable);
        assert!(import(
            &state,
            &auth,
            ConfigImportMode::Apply,
            false,
            document.clone()
        )
        .await
        .is_err());
        assert!(import(
            &state,
            &auth,
            ConfigImportMode::Plan,
            true,
            document.clone()
        )
        .await
        .is_err());

        let body = serde_json::json!({
            "document": document,
            "secrets": { format!("upstream_auth/{remote_key}"): CANARY_5292 },
        });
        let applied = import(&state, &auth, ConfigImportMode::Apply, false, body.clone())
            .await
            .expect("apply");
        assert!(applied.applied);

        let second = export_keys(&state, &auth, &keys).await;
        assert_eq!(content(&first), content(&second));

        // Re-planning (and re-applying) the same document changes nothing.
        let replan = import(&state, &auth, ConfigImportMode::Plan, false, body.clone())
            .await
            .unwrap();
        assert!(
            replan.create.is_empty() && replan.update.is_empty(),
            "{replan:?}"
        );
        assert_eq!(replan.unchanged.len(), 2);
        import(&state, &auth, ConfigImportMode::Apply, false, body.clone())
            .await
            .expect("re-apply");
        assert_eq!(
            content(&second),
            content(&export_keys(&state, &auth, &keys).await)
        );
        let stored_mode = |key: String| {
            let state = state.clone();
            let auth = auth.clone();
            async move {
                let Json(mode) =
                    repos::get_upstream_mode(State(state), Extension(Some(auth)), Path(key))
                        .await
                        .expect("get upstream mode");
                mode.upstream_mode
            }
        };
        assert_eq!(
            stored_mode(remote_key.clone()).await,
            crate::services::upstream_mode::UpstreamMode::CacheOnly
        );

        // #5407: a Remote put back online is planned as an `upstream_mode`
        // change, and apply makes it cache-only again.
        repos::set_upstream_mode(
            State(state.clone()),
            ext(),
            path(),
            Json(repos::SetUpstreamModeRequest {
                upstream_mode: crate::services::upstream_mode::UpstreamMode::Online,
            }),
        )
        .await
        .expect("upstream mode online");
        let drifted = import(&state, &auth, ConfigImportMode::Plan, false, body.clone())
            .await
            .unwrap();
        assert_eq!(
            drifted.update,
            [ConfigPlanUpdate {
                key: remote_key.clone(),
                changes: vec!["upstream_mode".into()],
            }]
        );
        import(&state, &auth, ConfigImportMode::Apply, false, body.clone())
            .await
            .expect("apply upstream mode");
        assert_eq!(
            stored_mode(remote_key.clone()).await,
            crate::services::upstream_mode::UpstreamMode::CacheOnly
        );
        assert_eq!(
            content(&second),
            content(&export_keys(&state, &auth, &keys).await)
        );

        // The audit insert is spawned (fire-and-forget): poll for it.
        let mut audited = 0i64;
        for _ in 0..50 {
            audited = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_log \
                 WHERE action = 'CONFIG_IMPORTED' AND user_id = $1",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            if audited >= 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(audited, 3, "one CONFIG_IMPORTED row per apply");

        delete_repo_by_key(&pool, &virtual_key).await;
        delete_repo_by_key(&pool, &remote_key).await;
        let _ = sqlx::query("DELETE FROM audit_log WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }
}
