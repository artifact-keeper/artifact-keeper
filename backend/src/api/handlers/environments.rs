//! Stored environments and the component -> environment reverse index
//! (#4054).
//!
//! #4053 renders an uploaded lockfile as SBOM documents and forgets it. These
//! endpoints STORE the parsed graph (as `(repository, name)`) and answer the
//! incident question — "which of our environments contain this component, and
//! what pulls it in?" — from the membership index, per platform, with the
//! inclusion chains.
//!
//! * `POST   /api/v1/repositories/{key}/environments` — ingest a lockfile
//!   (repo `write`); re-ingesting the same name replaces the stored graph.
//! * `GET    /api/v1/repositories/{key}/environments` — list.
//! * `GET    /api/v1/repositories/{key}/environments/{id}` — detail with
//!   per-scope counts.
//! * `DELETE /api/v1/repositories/{key}/environments/{id}` — delete (repo
//!   `delete`).
//! * `GET    /api/v1/environments/lookup?purl=…` — the reverse index across
//!   every stored environment the caller may read (same visibility rule as
//!   `require_visible`, rendered as a SQL clause).
//! * `GET    /api/v1/environments/advisory-transitions?since=…&until=…` —
//!   the #4055 event surface: environments BECOMING / CEASING to be affected
//!   as advisory data changes, same visibility rule.
//! * `GET    /api/v1/repositories/{key}/environments/{id}/advisories` — the
//!   environment's current affectedness state (#4055).

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, OpenApi};
use uuid::Uuid;

use crate::api::handlers::repositories::{
    member_read_visibility, require_repo_action, require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::environment_lock;
use crate::services::environment_reeval::{
    AffectednessRecord, EnvironmentReevalService, TransitionFilter, TransitionRecord,
    TRANSITION_NEW_AFFECTED, TRANSITION_NO_LONGER_AFFECTED,
};
use crate::services::environment_service::{
    clamp_max_paths, EnvironmentHit, EnvironmentService, LookupOutcome, ScopeCount,
    StoredEnvironment,
};
use crate::services::repository_service::RepositoryService;

/// Query for [`ingest_environment`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct IngestEnvironmentQuery {
    /// Lockfile file name; selects the parser (`pixi.lock`, `conda-lock.yml`,
    /// `package-lock.json`, `Cargo.lock`, `poetry.lock`, `uv.lock`).
    pub filename: String,
    /// Environment name within the repository. Defaults to the lockfile's
    /// base file name. Re-ingesting an existing name replaces its graph.
    pub name: Option<String>,
}

/// Query for [`lookup_environments`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct LookupEnvironmentsQuery {
    /// Component purl, e.g. from an advisory (`pkg:pypi/requests@2.31.0`).
    /// Qualifiers are stripped before lookup: advisories are
    /// name/version-scoped, so the index is keyed on the purl base.
    pub purl: String,
    /// Maximum inclusion paths returned per hit (1-64, default 8).
    pub max_paths: Option<u64>,
}

/// Query for [`list_advisory_transitions`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct AdvisoryTransitionsQuery {
    /// Restrict to one advisory id (e.g. `GHSA-j8r2-6p8f-2345`).
    pub advisory: Option<String>,
    /// Restrict to one transition kind: `new-affected` or
    /// `no-longer-affected`.
    pub kind: Option<String>,
    /// Only transitions detected at or after this RFC 3339 timestamp.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// Only transitions detected at or before this RFC 3339 timestamp.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// Page size (1-500, default 100).
    pub limit: Option<i64>,
}

/// Ingest a lockfile as a stored environment (#4054).
///
/// Parses the lockfile with the #4052 parser and stores its graph —
/// per-(environment, platform) package memberships and resolved edges — under
/// `(repository, name)`, replacing any graph previously stored under that
/// name. This is what makes the environment addressable by the reverse
/// index; the #4053 SBOM endpoint deliberately stores nothing.
#[utoipa::path(
    post,
    path = "/api/v1/repositories/{key}/environments",
    tag = "environments",
    params(IngestEnvironmentQuery, ("key" = String, Path, description = "Repository key")),
    request_body(
        description = "Raw lockfile bytes (pixi.lock, conda-lock.yml, package-lock.json, Cargo.lock, poetry.lock, uv.lock)",
        content = String,
        content_type = "application/octet-stream"
    ),
    responses(
        (status = 200, description = "Environment replaced (same name re-ingested)", body = Object),
        (status = 201, description = "Environment stored", body = Object),
        (status = 400, description = "Unrecognized, unhandled or unparseable lockfile", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository write permission required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn ingest_environment(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<IngestEnvironmentQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_action(&auth, repo.id, "write", &state.permission_service).await?;

    let env = environment_lock::parse_named_lockfile(&query.filename, body.as_ref())?;
    let name = query.name.as_deref().unwrap_or_else(|| {
        query
            .filename
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&query.filename)
    });
    let content_sha256 = format!("{:x}", Sha256::digest(body.as_ref()));

    let outcome = EnvironmentService::new(state.db.clone())
        .ingest(repo.id, name, &content_sha256, &env)
        .await?;

    let status = if outcome.replaced {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(ingest_envelope(&repo.key, name, &content_sha256, &outcome)),
    ))
}

/// The ingest response envelope. Pure, so the shape is unit-testable without
/// a `SharedState`.
pub(crate) fn ingest_envelope(
    repo_key: &str,
    name: &str,
    content_sha256: &str,
    outcome: &crate::services::environment_service::IngestOutcome,
) -> serde_json::Value {
    let summary = &outcome.summary;
    serde_json::json!({
        "id": outcome.id,
        "repository": repo_key,
        "name": name,
        "contentSha256": content_sha256,
        "replaced": outcome.replaced,
        "summary": {
            "scopes": summary.scopes,
            "memberships": summary.memberships,
            "distinctPackages": summary.distinct_packages,
            "edges": summary.edges,
            "unparsed": summary.unparsed,
            "missingDependencies": summary.missing_dependencies,
            "explainedAbsences": summary.explained_absences,
            "ambiguous": summary.ambiguous,
        },
    })
}

/// List the environments stored in a repository.
#[utoipa::path(
    get,
    path = "/api/v1/repositories/{key}/environments",
    tag = "environments",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "Stored environments, by name", body = Object),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_environments(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;

    let environments = EnvironmentService::new(state.db.clone())
        .list(repo.id)
        .await?;
    Ok(Json(serde_json::json!({
        "environments": environments.iter().map(environment_envelope).collect::<Vec<_>>(),
    })))
}

/// Show one stored environment with its per-scope counts.
#[utoipa::path(
    get,
    path = "/api/v1/repositories/{key}/environments/{id}",
    tag = "environments",
    params(("key" = String, Path, description = "Repository key"), ("id" = Uuid, Path, description = "Environment id")),
    responses(
        (status = 200, description = "Stored environment detail", body = Object),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or environment not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_environment(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;

    let (environment, scopes) = EnvironmentService::new(state.db.clone())
        .get(repo.id, id)
        .await?;
    let mut body = environment_envelope(&environment);
    body["scopes"] = serde_json::json!(scopes
        .iter()
        .map(|s: &ScopeCount| serde_json::json!({
            "environment": s.environment,
            "platform": s.platform,
            "memberships": s.memberships,
            "edges": s.edges,
        }))
        .collect::<Vec<_>>());
    Ok(Json(body))
}

/// Delete a stored environment (memberships and edges cascade).
#[utoipa::path(
    delete,
    path = "/api/v1/repositories/{key}/environments/{id}",
    tag = "environments",
    params(("key" = String, Path, description = "Repository key"), ("id" = Uuid, Path, description = "Environment id")),
    responses(
        (status = 204, description = "Environment deleted"),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository delete permission required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or environment not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_environment(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<StatusCode> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_action(&auth, repo.id, "delete", &state.permission_service).await?;

    let deleted = EnvironmentService::new(state.db.clone())
        .delete(repo.id, id)
        .await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("Environment not found".to_string()))
    }
}

/// The reverse index: which stored environments contain a component (#4054).
///
/// Given a component purl — typically straight out of an advisory — returns
/// every stored environment containing it, per (environment, platform)
/// scope, with the inclusion chains from a root down to the component. The
/// answer is restricted to repositories the caller may read, rendered by the
/// same visibility rule `require_visible` applies row by row. The membership
/// predicate is an index scan over the purl base, so the query holds at
/// realistic environment counts.
#[utoipa::path(
    get,
    path = "/api/v1/environments/lookup",
    tag = "environments",
    params(LookupEnvironmentsQuery),
    responses(
        (status = 200, description = "Affected environments per platform, with inclusion paths", body = Object),
        (status = 400, description = "Missing or empty purl", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn lookup_environments(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<LookupEnvironmentsQuery>,
) -> Result<Json<serde_json::Value>> {
    if query.purl.trim().is_empty() {
        return Err(AppError::Validation("`purl` must not be empty".to_string()));
    }
    let visibility = member_read_visibility(Some(&auth));
    let outcome = EnvironmentService::new(state.db.clone())
        .lookup_by_purl(&query.purl, &visibility, clamp_max_paths(query.max_paths))
        .await?;
    Ok(Json(lookup_envelope(&outcome)))
}

/// The lookup response envelope. Pure, so the shape is unit-testable.
pub(crate) fn lookup_envelope(outcome: &LookupOutcome) -> serde_json::Value {
    serde_json::json!({
        "query": {
            "purl": outcome.purl,
            "purlBase": outcome.purl_base,
        },
        "truncated": outcome.truncated,
        "hits": outcome.hits.iter().map(|hit: &EnvironmentHit| serde_json::json!({
            "environment": {"id": hit.environment_id, "name": hit.environment_name},
            "repository": {"id": hit.repository_id, "key": hit.repository_key},
            "scope": {
                "environment": hit.scope.environment,
                "platform": hit.scope.platform,
            },
            "package": {
                "name": hit.package_name,
                "version": hit.package_version,
                "purl": hit.package_purl,
            },
            "paths": hit.paths,
        })).collect::<Vec<_>>(),
    })
}

/// Affectedness transitions across every stored environment the caller may
/// read (#4055) — the event surface of environment re-evaluation.
///
/// Only TRANSITIONS are listed: an environment becoming affected by a newly
/// published advisory (`new-affected`) or ceasing to be affected
/// (`no-longer-affected` — withdrawal, or a fixed version shifting past the
/// stored one). Steady state is not an event and is not here. Visibility is
/// rendered by the same `require_visible` predicate the repository listing
/// uses, so a caller never learns that an environment in a repository they
/// cannot read transitioned.
#[utoipa::path(
    get,
    path = "/api/v1/environments/advisory-transitions",
    tag = "environments",
    params(AdvisoryTransitionsQuery),
    responses(
        (status = 200, description = "Affectedness transitions, newest first", body = Object),
        (status = 400, description = "Unknown transition kind", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_advisory_transitions(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<AdvisoryTransitionsQuery>,
) -> Result<Json<serde_json::Value>> {
    if let Some(kind) = query.kind.as_deref() {
        if kind != TRANSITION_NEW_AFFECTED && kind != TRANSITION_NO_LONGER_AFFECTED {
            return Err(AppError::Validation(format!(
                "`kind` must be `{TRANSITION_NEW_AFFECTED}` or `{TRANSITION_NO_LONGER_AFFECTED}`"
            )));
        }
    }
    let visibility = member_read_visibility(Some(&auth));
    let transitions =
        EnvironmentReevalService::read_only(state.db.clone(), state.event_bus.clone())
            .list_transitions(
                &visibility,
                &TransitionFilter {
                    advisory_id: query.advisory,
                    kind: query.kind,
                    since: query.since,
                    until: query.until,
                    limit: query.limit,
                },
            )
            .await?;
    Ok(Json(transitions_envelope(&transitions)))
}

/// The transitions response envelope. Pure, so the shape is unit-testable.
pub(crate) fn transitions_envelope(transitions: &[TransitionRecord]) -> serde_json::Value {
    serde_json::json!({
        "transitions": transitions.iter().map(|t: &TransitionRecord| serde_json::json!({
            "environment": {"id": t.environment_id, "name": t.environment_name},
            "repository": {"id": t.repository_id, "key": t.repository_key},
            "advisory": {
                "id": t.advisory_id,
                "summary": t.summary,
                "severity": t.severity,
                "fixedVersion": t.fixed_version,
                "sourceUrl": t.source_url,
            },
            "package": {"ecosystem": t.ecosystem, "name": t.name, "version": t.version},
            "kind": t.kind,
            "detectedAt": t.detected_at,
        })).collect::<Vec<_>>(),
    })
}

/// The advisories currently affecting one stored environment (#4055): its
/// present affectedness state, as last evaluated against the feeds.
#[utoipa::path(
    get,
    path = "/api/v1/repositories/{key}/environments/{id}/advisories",
    tag = "environments",
    params(("key" = String, Path, description = "Repository key"), ("id" = Uuid, Path, description = "Environment id")),
    responses(
        (status = 200, description = "Current affectedness of the stored environment", body = Object),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or environment not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_environment_advisories(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;

    // Existence check through the repo-scoped getter, so an id from another
    // tenant's repository is a 404, not an empty list.
    EnvironmentService::new(state.db.clone())
        .get(repo.id, id)
        .await?;
    let advisories = EnvironmentReevalService::read_only(state.db.clone(), state.event_bus.clone())
        .environment_advisories(id)
        .await?;
    Ok(Json(affectedness_envelope(&advisories)))
}

/// The current-affectedness response envelope. Pure, so the shape is
/// unit-testable.
pub(crate) fn affectedness_envelope(advisories: &[AffectednessRecord]) -> serde_json::Value {
    serde_json::json!({
        "affected": advisories.iter().map(|a: &AffectednessRecord| serde_json::json!({
            "advisory": {
                "id": a.advisory_id,
                "summary": a.summary,
                "severity": a.severity,
                "fixedVersion": a.fixed_version,
                "sourceUrl": a.source_url,
            },
            "package": {"ecosystem": a.ecosystem, "name": a.name, "version": a.version},
            "affectedSince": a.affected_since,
            "lastEvaluatedAt": a.last_evaluated_at,
        })).collect::<Vec<_>>(),
    })
}

/// A stored environment as JSON. Pure, so the shape is unit-testable.
pub(crate) fn environment_envelope(environment: &StoredEnvironment) -> serde_json::Value {
    serde_json::json!({
        "id": environment.id,
        "name": environment.name,
        "lockfileFormat": environment.lockfile_format,
        "contentSha256": environment.content_sha256,
        "summary": environment.summary,
        "createdAt": environment.created_at,
        "updatedAt": environment.updated_at,
    })
}

/// Repository-scoped environment routes, merged into the `/repositories`
/// nest (which carries the optional-auth middleware).
pub fn repo_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/environments",
            post(ingest_environment).get(list_environments),
        )
        .route(
            "/:key/environments/:id",
            get(get_environment).delete(delete_environment),
        )
        .route(
            "/:key/environments/:id/advisories",
            get(get_environment_advisories),
        )
}

/// The global environment routes (the reverse index), nested at
/// `/environments` with the full-auth middleware.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/lookup", get(lookup_environments))
        .route("/advisory-transitions", get(list_advisory_transitions))
}

#[derive(OpenApi)]
#[openapi(paths(
    ingest_environment,
    list_environments,
    get_environment,
    delete_environment,
    lookup_environments,
    list_advisory_transitions,
    get_environment_advisories,
))]
pub struct EnvironmentsApiDoc;

#[cfg(test)]
// streaming-invariant: test scaffolding exempt — buffering bounded response
// bodies in DB-backed handler tests is not an artifact path (#1608).
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const ENV_A: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: linux-64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: linux-64
    dependencies: {}
"#;

    async fn post_lockfile(
        router: &axum::Router,
        repo_key: &str,
        name: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/{repo_key}/environments?filename=conda-lock.yml&name={name}"
                    ))
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .expect("ingest response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// End to end through both routers: ingest stores the graph, the reverse
    /// index names the environment with the inclusion path, re-ingest
    /// reports the replacement.
    #[tokio::test]
    async fn ingest_then_lookup_end_to_end() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let repo_router = fx.router_with_auth(repo_router());
        let global_router = tdh::router_with_auth_ext(router(), fx.state.clone(), auth);

        let (status, created) =
            post_lockfile(&repo_router, &fx.repo_key, "data-science", ENV_A).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["name"], "data-science");
        assert_eq!(created["replaced"], false);
        assert_eq!(created["summary"]["memberships"], 2);

        let (status, replaced) =
            post_lockfile(&repo_router, &fx.repo_key, "data-science", ENV_A).await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        assert_eq!(replaced["replaced"], true);

        let response = global_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/lookup?purl=pkg%3Aconda%2Flibwebp%401.3.2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("lookup response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["query"]["purlBase"], "pkg:conda/libwebp@1.3.2");
        let hits = body["hits"].as_array().expect("hits array");
        let hit = hits
            .iter()
            .find(|h| h["environment"]["name"] == "data-science")
            .expect("data-science named as affected");
        assert_eq!(hit["scope"]["platform"], "linux-64");
        assert_eq!(
            hit["paths"],
            serde_json::json!([["pillow@10.0.0", "libwebp@1.3.2"]])
        );
        fx.teardown().await;
    }

    /// The reverse index must not answer about repositories the caller
    /// cannot read.
    #[tokio::test]
    async fn lookup_hides_invisible_repositories() {
        let Some(owner) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let owner_router = owner.router_with_auth(repo_router());
        let (status, _) = post_lockfile(&owner_router, &owner.repo_key, "secret-env", ENV_A).await;
        assert_eq!(status, StatusCode::CREATED);

        let Some(stranger) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let stranger_router = tdh::router_with_auth_ext(
            router(),
            stranger.state.clone(),
            tdh::make_auth(stranger.user_id, &stranger.username),
        );
        let response = stranger_router
            .oneshot(
                Request::builder()
                    .uri("/lookup?purl=pkg%3Aconda%2Flibwebp%401.3.2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("lookup response");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let hits = body["hits"].as_array().expect("hits array");
        assert!(
            hits.iter()
                .all(|h| h["environment"]["name"] != "secret-env"),
            "a non-member must not learn that the environment exists: {hits:?}"
        );
        owner.teardown().await;
        stranger.teardown().await;
    }

    #[test]
    fn clamp_applies_to_lookup_query() {
        assert_eq!(clamp_max_paths(Some(0)), 1);
        assert_eq!(clamp_max_paths(Some(10_000)), 64);
    }

    /// Env with a pip pin: the already-installed component an advisory
    /// lands against (#4055 handler test). The package name is unique to
    /// this test — a delta re-evaluates every stored environment containing
    /// the package, so sharing a name with the service-level tests would
    /// let parallel suites rewrite each other's state rows.
    const ENV_REQUESTS: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: req4055-http
    version: 2.18.4
    manager: pip
    platform: linux-64
    dependencies: {}
"#;

    /// End to end through the #4055 read paths: a detected advisory against
    /// the stored component produces a transition listed by the global
    /// endpoint (since/until-scoped) and current state on the per-env one.
    #[tokio::test]
    async fn advisory_transition_and_state_endpoints() {
        use crate::services::environment_reeval::{
            AdvisoryDelta, EnvironmentReevalService, TRANSITION_NEW_AFFECTED,
        };
        use crate::services::event_bus::EventBus;
        use crate::services::scanner_service::AdvisoryClient;
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let repo_router = fx.router_with_auth(repo_router());
        let global_router = tdh::router_with_auth_ext(router(), fx.state.clone(), auth);

        let (status, created) =
            post_lockfile(&repo_router, &fx.repo_key, "ml-serving", ENV_REQUESTS).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let env_id = created["id"].as_str().expect("environment id");

        // The feed names an advisory against the pinned package. The
        // responder answers one slot PER QUERY: a fixed single-result body
        // would read as a short answer for any larger batch, and a short
        // answer is degraded by design (#4080).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(move |req: &wiremock::Request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or(serde_json::json!({}));
                let n = body["queries"].as_array().map(Vec::len).unwrap_or(0);
                let results: Vec<serde_json::Value> = (0..n)
                    .map(|_| {
                        serde_json::json!({
                            "vulns": [{
                                "id": "GHSA-j8r2-6p8f-2345",
                                "summary": "requests smuggles headers",
                                "database_specific": { "severity": "HIGH" },
                                "affected": [{
                                    "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "2.20.0" }] }]
                                }]
                            }]
                        })
                    })
                    .collect();
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "results": results }))
            })
            .mount(&server)
            .await;
        let reeval = EnvironmentReevalService::new(
            fx.pool.clone(),
            Arc::new(AdvisoryClient::for_test(
                format!("{}/v1/querybatch", server.uri()),
                Duration::from_millis(1),
            )),
            Arc::new(EventBus::new(16)),
        );
        reeval
            .process_delta(&AdvisoryDelta {
                ecosystem: "PyPI".to_string(),
                name: "req4055-http".to_string(),
                advisory_ids: vec!["GHSA-j8r2-6p8f-2345".to_string()],
            })
            .await
            .expect("process delta");

        // The transitions endpoint surfaces the new-affected event.
        let response = global_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/advisory-transitions?advisory=GHSA-j8r2-6p8f-2345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("transitions response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let transitions = body["transitions"].as_array().expect("transitions array");
        let mine = transitions
            .iter()
            .find(|t| t["environment"]["id"] == env_id)
            .expect("my environment's transition listed");
        assert_eq!(mine["kind"], TRANSITION_NEW_AFFECTED);
        assert_eq!(mine["package"]["name"], "req4055-http");
        assert_eq!(mine["package"]["version"], "2.18.4");
        assert_eq!(mine["advisory"]["severity"], "high");
        assert_eq!(mine["advisory"]["fixedVersion"], "2.20.0");

        // until in the past excludes it.
        let response = global_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/advisory-transitions?until=2000-01-01T00:00:00Z")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("transitions response");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(body["transitions"]
            .as_array()
            .expect("array")
            .iter()
            .all(|t| t["environment"]["id"] != env_id));

        // An unknown kind is a 400, not a silent empty page.
        let response = global_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/advisory-transitions?kind=bogus")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("transitions response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // The per-environment endpoint answers current state.
        let response = repo_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/{}/environments/{}/advisories",
                        fx.repo_key, env_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("advisories response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let affected = body["affected"].as_array().expect("affected array");
        assert_eq!(affected.len(), 1, "{affected:?}");
        assert_eq!(affected[0]["advisory"]["id"], "GHSA-j8r2-6p8f-2345");
        assert_eq!(affected[0]["package"]["name"], "req4055-http");

        fx.teardown().await;
    }
}
