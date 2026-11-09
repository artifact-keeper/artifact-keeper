//! Edges of the MCP registry surface (#5253, Phase 2/3):
//!
//! - `GET /mcp/{repo}/v0.1/x/com.artifactkeeper/holds`: the held versions of
//!   a repository with their hold class and reason, for CI tooling
//!   (reason-gated; everyone else gets the unknown-name `404`).
//! - `GET /mcp/{repo}/v0.1/openapi.yaml`: the upstream registry API
//!   specification this surface implements, vendored verbatim.
//! - `POST /mcp/{repo}/v0/auth/github-oidc` (and `/v0.1`): upstream's GitHub
//!   OIDC login bridged to the CI OIDC exchange, so
//!   `mcp-publisher login github-oidc --registry https://ak/mcp/{repo}`
//!   works; every other `/auth/*` answers `501`.
//! - `MCP_DEFAULT_REPO`: host-level `/v0.1/...` and `/v0/...` onto one repo.
//! - The namespace write gate every MCP write handler calls.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;

use super::mcp;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::AppError;
use crate::formats::mcp::{self as fmt, GateAudience, ServeDecision};
use crate::services::mcp_packages::GateCtx;

type HandlerResult = Result<Response, Response>;

/// The vendored upstream specification (`docs/reference/api/openapi.yaml`).
pub const OPENAPI_YAML: &str = include_str!("../../formats/mcp_openapi.yaml");
/// Request body cap of the auth bridge (an OIDC assertion is a few KiB).
pub const AUTH_BODY_MAX: usize = 16 * 1024;
/// The AK extension namespace on the registry surface.
pub const HOLDS_PATH: &str = "/x/com.artifactkeeper/holds";

/// Read routes of this module for one API version, merged into the MCP read
/// router (behind repository visibility).
pub fn read_routes(v: &str) -> Router<SharedState> {
    Router::new()
        .route(&format!("/:repo_key/{v}/openapi.yaml"), get(openapi))
        .route(&format!("/:repo_key/{v}{HOLDS_PATH}"), get(holds))
}

/// The credential-exchange routes, mounted OUTSIDE the repository
/// visibility middleware (the OIDC assertion in the body is the credential;
/// an anonymous POST to a private repository must still reach it).
pub fn public_router() -> Router<SharedState> {
    let mut r = Router::new();
    for v in mcp::API_VERSIONS {
        r = r
            .route(
                &format!("{}/:repo_key/{v}/auth/github-oidc", mcp::MOUNT_PREFIX),
                post(github_oidc),
            )
            .route(
                &format!("{}/:repo_key/{v}/auth/*rest", mcp::MOUNT_PREFIX),
                any(auth_not_supported),
            );
    }
    r.layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_MAX))
}

// ---------------------------------------------------------------------------
// GET /openapi.yaml
// ---------------------------------------------------------------------------

async fn openapi(State(state): State<SharedState>, Path(repo_key): Path<String>) -> HandlerResult {
    mcp::resolve_mcp_repo(&state.db, &repo_key).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/yaml")],
        OPENAPI_YAML,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /x/com.artifactkeeper/holds
// ---------------------------------------------------------------------------

/// One held version as the holds listing reports it: the reason-gated
/// refusal body without the RFC 9457 envelope members, plus the HTTP status
/// an exact read answers (`404`, or `503` for an unevaluable gate).
pub fn hold_entry(status: u16, body: &serde_json::Value) -> serde_json::Value {
    let mut entry = body.clone();
    if let Some(o) = entry.as_object_mut() {
        o.remove("type");
        o.remove("title");
        o.insert("status".into(), status.into());
    }
    entry
}

async fn holds(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    base: crate::api::extractors::RequestBaseUrl,
) -> HandlerResult {
    let repo = mcp::resolve_mcp_repo(&state.db, &repo_key).await?;
    // Holds are reason-gated: a reader learns nothing, not even that the
    // listing exists (an empty list would read as "nothing is held"). A
    // Virtual holds nothing of its own; ask its members.
    if repo.repo_type == "virtual"
        || mcp::audience(&state.db, auth.as_ref(), repo.id).await != GateAudience::ReasonGated
    {
        return Err(mcp::not_found());
    }
    let seal = mcp::cursor_seal(&state);
    let q = mcp::parse_list_query(&query, |c| {
        seal.decode_position(repo.id, fmt::cursor_kind::HOLDS, c)
            .map(|(n, v)| fmt::ListingResume::after(&n, &v))
    })
    .map_err(mcp::mcp_error)?;
    let encode = |n: &str, v: &str| seal.encode_position(repo.id, fmt::cursor_kind::HOLDS, n, v);
    let want = q.limit as usize;
    let ctx = GateCtx::of(&state, false);
    let mut out: Vec<(String, String, serde_json::Value)> = Vec::new();
    // Holds list only held rows to a holder: the position may name one.
    let mut after = q.cursor.after.clone();
    let mut read = 0usize;
    let mut resume: Option<String> = None;
    loop {
        let batch =
            mcp::fetch_listing_batch(&state.db, repo.id, &q, after.as_ref(), q.limit + 1).await?;
        read += batch.raw_len;
        let exhausted = (batch.raw_len as i64) <= q.limit;
        if let Some(last) = batch.last {
            after = Some(last);
        }
        for row in &batch.rows {
            let instance = mcp::instance_url(base.as_str(), &repo.key, &row.name, &row.version);
            let decision =
                mcp::decide_row(ctx, row, false, GateAudience::ReasonGated, instance).await;
            if let ServeDecision::Refuse { status, body, .. } = decision {
                out.push((
                    row.name.clone(),
                    row.version.clone(),
                    hold_entry(status, &body),
                ));
            }
        }
        if out.len() > want || exhausted {
            break;
        }
        if read >= mcp::MAX_LISTING_ROWS {
            resume = after.as_ref().map(|(n, v)| encode(n, v));
            break;
        }
    }
    let next = if out.len() > want {
        Some(encode(&out[want - 1].0, &out[want - 1].1))
    } else {
        resume
    };
    out.truncate(want);
    let mut metadata = serde_json::json!({"count": out.len()});
    if let Some(c) = next {
        metadata["nextCursor"] = c.into();
    }
    let holds: Vec<serde_json::Value> = out.into_iter().map(|(_, _, e)| e).collect();
    let mut resp = mcp::json_ok(
        StatusCode::OK,
        &serde_json::json!({"holds": holds, "metadata": metadata}),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// POST /auth/github-oidc
// ---------------------------------------------------------------------------

/// Upstream's `GitHubOIDCTokenExchangeInput` body.
#[derive(Debug, serde::Deserialize)]
struct OidcExchange {
    oidc_token: String,
}

/// Upstream's `auth.TokenResponse`: what `mcp-publisher` reads.
pub fn token_response(token: &str, now_unix: i64, expires_in: u64) -> serde_json::Value {
    serde_json::json!({
        "registry_token": token,
        "expires_at": now_unix.saturating_add(expires_in as i64),
    })
}

/// The status and code of a failed exchange: credential and policy failures
/// are upstream's `401`, a capacity shed stays `503`.
pub fn exchange_failure(e: &AppError) -> (u16, &'static str) {
    match e {
        AppError::ServiceUnavailable(_) => (503, "mcp_unavailable"),
        AppError::Database(_) | AppError::Internal(_) => (500, "mcp_internal_error"),
        _ => (401, "mcp_unauthorized"),
    }
}

async fn github_oidc(State(state): State<SharedState>, body: Bytes) -> HandlerResult {
    let req: OidcExchange = serde_json::from_slice(&body).map_err(|_| {
        mcp::problem(
            400,
            "mcp_bad_request",
            "the body must be {\"oidc_token\": \"<GitHub Actions OIDC token>\"}",
            serde_json::json!({}),
        )
    })?;
    match super::ci_auth::exchange_assertion(&state, req.oidc_token.trim(), None).await {
        Ok((_user, tokens, _claims)) => Ok(mcp::json_ok(
            StatusCode::OK,
            &token_response(
                &tokens.access_token,
                chrono::Utc::now().timestamp(),
                tokens.expires_in,
            ),
        )),
        Err(e) => {
            let (status, code) = exchange_failure(&e);
            tracing::info!(error = %e, "MCP github-oidc token exchange refused");
            Err(mcp::problem(
                status,
                code,
                "Token exchange failed: the OIDC token was not accepted by this instance's CI \
                 OIDC configuration",
                serde_json::json!({}),
            ))
        }
    }
}

async fn auth_not_supported() -> Response {
    mcp::problem(
        501,
        "mcp_auth_not_supported",
        "This registry authenticates with Artifact Keeper credentials: put an Artifact Keeper \
         API token in ~/.config/mcp-publisher/token.json (method \"none\"), or run \
         `mcp-publisher login github-oidc` from GitHub Actions",
        serde_json::json!({}),
    )
}

// ---------------------------------------------------------------------------
// The namespace write gate
// ---------------------------------------------------------------------------

/// Refuse an MCP write of `name` the caller holds no grant for (see
/// `services::mcp_namespaces`): `403 mcp_namespace_not_granted`.
pub(crate) async fn require_namespace_write(
    state: &SharedState,
    auth: &AuthExtension,
    repo_id: uuid::Uuid,
    name: &str,
    action: &str,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let bearer = crate::services::mcp_namespaces::bearer_of(headers);
    match crate::services::mcp_namespaces::authorize_write(
        &state.db, auth, repo_id, name, action, bearer,
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(mcp::problem(
            403,
            "mcp_namespace_not_granted",
            &format!(
                "this credential holds no grant for namespace '{}' in this repository",
                fmt::namespace_of(name)
            ),
            serde_json::json!({}),
        )),
        Err(e) => Err(mcp::internal(e)),
    }
}

// ---------------------------------------------------------------------------
// MCP_DEFAULT_REPO
// ---------------------------------------------------------------------------

/// The `/mcp/{repo}/...` path a host-level registry path maps to, or `None`
/// for every other path (only `/v0.1` and `/v0` and what is below them).
pub fn default_repo_path(path: &str, repo: &str) -> Option<String> {
    mcp::API_VERSIONS.iter().find_map(|v| {
        let prefix = format!("/{v}");
        let rest = path.strip_prefix(&prefix)?;
        (rest.is_empty() || rest.starts_with('/'))
            .then(|| format!("{}/{repo}{prefix}{rest}", mcp::MOUNT_PREFIX))
    })
}

/// A usable `MCP_DEFAULT_REPO` value: a plain repository key.
pub fn default_repo_from_env(value: Option<&str>) -> Option<String> {
    let v = value?.trim();
    let ok = !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok && !v.is_empty() {
        tracing::warn!(
            value = v,
            "MCP_DEFAULT_REPO is not a repository key; ignored"
        );
    }
    ok.then(|| v.to_string())
}

/// Wrap `app` so host-level `/v0.1/...` and `/v0/...` requests are served by
/// `/mcp/{repo}/...` (the rewrite runs before routing, so every middleware
/// sees the repository path). `None` leaves `app` unchanged.
pub fn mount_default_repo(app: Router, repo: Option<String>) -> Router {
    let Some(repo) = repo else {
        return app;
    };
    tracing::info!(repo = %repo, "MCP registry API served at the host root (MCP_DEFAULT_REPO)");
    Router::new()
        .fallback_service(app)
        .layer(axum::middleware::map_request(
            move |mut req: axum::extract::Request| {
                let repo = repo.clone();
                async move {
                    if let Some(path) = default_repo_path(req.uri().path(), &repo) {
                        let pq = match req.uri().query() {
                            Some(q) => format!("{path}?{q}"),
                            None => path,
                        };
                        let mut parts = req.uri().clone().into_parts();
                        if let Ok(pq) = pq.parse() {
                            parts.path_and_query = Some(pq);
                            if let Ok(uri) = axum::http::Uri::from_parts(parts) {
                                *req.uri_mut() = uri;
                            }
                        }
                    }
                    req
                }
            },
        ))
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_repo_paths_map_only_the_registry_prefixes() {
        assert_eq!(
            default_repo_path("/v0.1/servers", "mcp").as_deref(),
            Some("/mcp/mcp/v0.1/servers")
        );
        assert_eq!(
            default_repo_path("/v0/auth/github-oidc", "r").as_deref(),
            Some("/mcp/r/v0/auth/github-oidc")
        );
        assert_eq!(
            default_repo_path("/v0.1", "r").as_deref(),
            Some("/mcp/r/v0.1")
        );
        for other in [
            "/v2/",
            "/v0.2/servers",
            "/v01/x",
            "/api/v1/repositories",
            "/mcp/r/v0.1/servers",
            "/",
        ] {
            assert_eq!(default_repo_path(other, "r"), None, "{other}");
        }
        assert_eq!(
            default_repo_from_env(Some(" mcp-local ")).as_deref(),
            Some("mcp-local")
        );
        for bad in [None, Some(""), Some("a/b"), Some("../x")] {
            assert_eq!(default_repo_from_env(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn mounted_default_repo_rewrites_before_routing() {
        use tower::ServiceExt as _;
        let inner = Router::new()
            .route(
                "/mcp/:repo/v0.1/servers",
                get(|Path(r): Path<String>| async move { r }),
            )
            .route("/v2/", get(|| async { "oci" }));
        let app = mount_default_repo(inner.clone(), Some("dflt".into()));
        let call = |app: Router, uri: &'static str| async move {
            let resp = app
                .oneshot(
                    axum::http::Request::get(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            (status, String::from_utf8_lossy(&body).to_string())
        };
        assert_eq!(
            call(app.clone(), "/v0.1/servers?limit=1").await,
            (StatusCode::OK, "dflt".into())
        );
        assert_eq!(
            call(app.clone(), "/mcp/other/v0.1/servers").await,
            (StatusCode::OK, "other".into())
        );
        assert_eq!(call(app, "/v2/").await, (StatusCode::OK, "oci".into()));
        assert_eq!(
            call(mount_default_repo(inner, None), "/v0.1/servers")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn token_response_has_upstreams_shape() {
        assert_eq!(
            token_response("t", 100, 900),
            serde_json::json!({"registry_token": "t", "expires_at": 1000})
        );
        assert_eq!(
            exchange_failure(&AppError::Authentication("x".into())).0,
            401
        );
        assert_eq!(exchange_failure(&AppError::NotFound("x".into())).0, 401);
        assert_eq!(
            exchange_failure(&AppError::ServiceUnavailable("x".into())).0,
            503
        );
        assert_eq!(exchange_failure(&AppError::Internal("x".into())).0, 500);
    }

    #[test]
    fn hold_entries_drop_the_envelope() {
        let body = fmt::problem_body(
            404,
            "mcp_pending_review",
            "held",
            serde_json::json!({"name": "a/b", "version": "1", "hold": "quarantine"}),
        );
        let e = hold_entry(404, &body);
        assert!(e.get("type").is_none() && e.get("title").is_none());
        assert_eq!(
            (e["status"].as_u64(), e["error"].as_str()),
            (Some(404), Some("mcp_pending_review"))
        );
        assert!(OPENAPI_YAML.contains("/v0.1/servers"));
    }
}
