//! Shadow evaluation of the IAM decision function on `/api/v1` (#4214).
//!
//! For every route that declares a catalog permission, the legacy handler
//! answers as before; after the response the same request is decided by
//! [`decide`] over the cached policy snapshot, and the two outcomes are
//! compared and reported. Nothing here can change a response: the comparison
//! runs in a spawned task after the response is built, behind a bounded
//! semaphore, with a panic contained and counted.
//!
//! The layer sits above the per-nest authentication middleware, so the
//! principal, the presented API token and any existence-hiding refusal reach
//! it through [`shadow_marker`]'s task-local recorder rather than through
//! request extensions.
//!
//! Enabled by `IAM_SHADOW_EVALUATION`; off by default.

use std::collections::HashMap;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, RawPathParams, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Utc};
use futures::FutureExt;
use metrics::counter;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::api::authz::catalog::Permission;
use crate::api::authz::declaration::{Resolver, RouteRequirement};
use crate::api::authz::registry::{RouteRegistry, API_V1_PREFIX};
use crate::api::authz::shadow_marker::{self, Recorded};
use crate::api::middleware::client_ip::current_verified_client_ip;
use crate::config::Config;
use crate::services::iam_decision::provider::SnapshotProvider;
use crate::services::iam_decision::{decide, Caller, Decision, Principal, RequestContext};
use crate::services::iam_legacy_projection::{CredentialRef, ScopeRef};

/// Comparisons in flight at once; beyond this a comparison is dropped.
pub const SHADOW_PERMITS: usize = 64;
/// How long a comparison waits for a snapshot.
pub const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);
/// Divergence log records per route and minute.
pub const LOG_LIMIT_PER_MINUTE: u32 = 10;

/// The legacy outcome, read from the final response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyOutcome {
    Permit,
    Refuse,
    /// The response does not say whether access was granted: an unmarked 404,
    /// a 429, or a server error.
    Unknown,
}

/// Classify the legacy response. A 404 is a refusal only when a hiding helper
/// marked it; the same mark on any other status (a list that filtered out
/// some rows) does not make the request a refusal.
pub fn legacy_outcome(status: StatusCode, hidden_refusal: bool) -> LegacyOutcome {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => LegacyOutcome::Refuse,
        StatusCode::NOT_FOUND if hidden_refusal => LegacyOutcome::Refuse,
        StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS => LegacyOutcome::Unknown,
        s if s.is_server_error() => LegacyOutcome::Unknown,
        _ => LegacyOutcome::Permit,
    }
}

/// The result of one comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Agree,
    /// Legacy permitted, the new decision refuses.
    NewStricter,
    /// Legacy refused, the new decision permits.
    NewWider,
    /// The new decision could not be made from the snapshot.
    NewUnavailable,
    /// No comparison was possible; the reason is a fixed label.
    Inconclusive(&'static str),
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Agree => "agree",
            Class::NewStricter => "new_stricter",
            Class::NewWider => "new_wider",
            Class::NewUnavailable => "new_unavailable",
            Class::Inconclusive(_) => "inconclusive",
        }
    }

    pub fn is_divergence(self) -> bool {
        matches!(
            self,
            Class::NewStricter | Class::NewWider | Class::NewUnavailable
        )
    }
}

/// Compare a legacy outcome with a decision.
pub fn classify(legacy: LegacyOutcome, decision: &Decision) -> Class {
    match (legacy, decision) {
        (_, Decision::Unavailable { .. }) => Class::NewUnavailable,
        (LegacyOutcome::Unknown, _) => Class::Inconclusive("legacy_unknown"),
        (LegacyOutcome::Permit, Decision::Permit { .. })
        | (LegacyOutcome::Refuse, Decision::Refuse { .. }) => Class::Agree,
        (LegacyOutcome::Permit, Decision::Refuse { .. }) => Class::NewStricter,
        (LegacyOutcome::Refuse, Decision::Permit { .. }) => Class::NewWider,
    }
}

/// The principal the legacy path authenticated, or anonymous.
pub fn principal_of(recorded: &Recorded) -> Principal {
    match recorded.principal {
        Some(p) if p.is_service_account => Principal::ServiceAccount(p.user_id),
        Some(p) => Principal::User(p.user_id),
        None => Principal::Anonymous,
    }
}

/// The caller to decide for. A restricted credential whose ceiling the
/// snapshot cannot name (a JWT exchanged from a token or minted by a CI
/// exchange, or an API token whose id was not recorded) is not decided
/// without its ceiling: that would report divergences the credential cannot
/// cause.
pub fn caller_of(recorded: &Recorded) -> Result<Caller, &'static str> {
    let principal = principal_of(recorded);
    let Some(p) = recorded.principal else {
        return Ok(Caller::anonymous());
    };
    match (p.is_api_token, recorded.api_token) {
        (true, Some(id)) => Ok(Caller::with_credential(principal, CredentialRef::Token(id))),
        (true, None) => Err("unattributed_credential"),
        (false, _) if p.restricted => Err("unattributed_credential"),
        (false, _) => Ok(Caller::session(principal)),
    }
}

/// What the layer captured from the request before the handler ran.
#[derive(Debug, Clone)]
pub struct Pending {
    pub method: String,
    pub route: String,
    pub permission: Permission,
    pub resolver: &'static Resolver,
    /// The value of the resolver's path parameter, if it names one.
    pub param: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub now: DateTime<Utc>,
}

/// One finished comparison, as reported.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub route: String,
    pub method: String,
    pub permission: Permission,
    pub principal: Principal,
    pub resource: Option<ScopeRef>,
    pub legacy_status: u16,
    pub legacy: LegacyOutcome,
    pub decision: Option<Decision>,
    pub class: Class,
}

/// Fixed-window rate limit for the divergence log, per route.
#[derive(Default)]
struct LogLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl LogLimiter {
    fn admit(&self, route: &str, limit: u32) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = windows.entry(route.to_string()).or_insert((now, 0));
        if now.duration_since(window.0) >= Duration::from_secs(60) {
            *window = (now, 0);
        }
        if window.1 < limit {
            window.1 += 1;
            true
        } else {
            false
        }
    }
}

/// The shadow layer's state, shared by every request.
pub struct IamShadow {
    registry: RouteRegistry,
    pub provider: Arc<SnapshotProvider>,
    db: PgPool,
    permits: Arc<Semaphore>,
    snapshot_timeout: Duration,
    log_limiter: LogLimiter,
    observer: Option<tokio::sync::mpsc::UnboundedSender<Comparison>>,
}

impl IamShadow {
    pub fn new(registry: RouteRegistry, provider: Arc<SnapshotProvider>, db: PgPool) -> IamShadow {
        IamShadow {
            registry,
            provider,
            db,
            permits: Arc::new(Semaphore::new(SHADOW_PERMITS)),
            snapshot_timeout: SNAPSHOT_TIMEOUT,
            log_limiter: LogLimiter::default(),
            observer: None,
        }
    }

    /// The layer for this process, or `None` when `IAM_SHADOW_EVALUATION` is
    /// off or the declarations cannot be read (logged; the API is unaffected).
    pub fn from_config(db: &PgPool, config: &Config) -> Option<Arc<IamShadow>> {
        if !config.iam_shadow_evaluation {
            return None;
        }
        match RouteRegistry::from_api_doc(&crate::api::openapi::build_openapi()) {
            Ok(registry) => {
                tracing::info!(
                    declared = registry.declared().count(),
                    "IAM shadow evaluation enabled on /api/v1"
                );
                Some(Arc::new(IamShadow::new(
                    registry,
                    Arc::new(SnapshotProvider::for_database(db.clone())),
                    db.clone(),
                )))
            }
            Err(errors) => {
                tracing::error!(
                    errors = errors.len(),
                    "IAM shadow evaluation disabled: invalid authorization declarations"
                );
                None
            }
        }
    }

    pub fn with_limits(mut self, permits: usize, snapshot_timeout: Duration) -> IamShadow {
        self.permits = Arc::new(Semaphore::new(permits));
        self.snapshot_timeout = snapshot_timeout;
        self
    }

    /// Send every finished comparison to `observer` as well (tests).
    pub fn with_observer(
        mut self,
        observer: tokio::sync::mpsc::UnboundedSender<Comparison>,
    ) -> IamShadow {
        self.observer = Some(observer);
        self
    }

    /// The declared permission of a matched route, with what the comparison
    /// needs from the request. `None` for a route that declares no permission.
    pub fn capture(&self, method: &str, matched: &str, params: &[(&str, &str)]) -> Option<Pending> {
        let prefixed;
        let route = if matched.starts_with(API_V1_PREFIX) {
            matched
        } else {
            prefixed = format!("{API_V1_PREFIX}{matched}");
            &prefixed
        };
        let RouteRequirement::Permission {
            permission,
            resolver,
        } = *self.registry.requirement(method, route)?
        else {
            return None;
        };
        let param = resolver.id.split_once(':').and_then(|(_, name)| {
            params
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        });
        Some(Pending {
            method: method.to_uppercase(),
            route: route.to_string(),
            permission,
            resolver,
            param,
            client_ip: current_verified_client_ip(),
            now: Utc::now(),
        })
    }

    /// Start the comparison off the request path. Drops it, counted, when
    /// every permit is taken.
    pub fn spawn_comparison(
        self: &Arc<Self>,
        pending: Pending,
        status: StatusCode,
        recorded: Recorded,
    ) {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            counter!("ak_iam_shadow_dropped_total").increment(1);
            return;
        };
        let shadow = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let route = pending.route.clone();
            let run = AssertUnwindSafe(shadow.compare(pending, status, recorded));
            if run.catch_unwind().await.is_err() {
                counter!("ak_iam_shadow_panicked_total").increment(1);
                tracing::warn!(target: "iam_shadow", %route, "IAM shadow comparison panicked");
            }
        });
    }

    /// Decide, classify and report one request.
    pub async fn compare(
        &self,
        pending: Pending,
        status: StatusCode,
        recorded: Recorded,
    ) -> Comparison {
        let legacy = legacy_outcome(status, recorded.hidden_refusal);
        let mut comparison = Comparison {
            route: pending.route.clone(),
            method: pending.method.clone(),
            permission: pending.permission,
            principal: principal_of(&recorded),
            resource: None,
            legacy_status: status.as_u16(),
            legacy,
            decision: None,
            class: Class::Inconclusive("legacy_unknown"),
        };
        if legacy != LegacyOutcome::Unknown {
            match self.decide_for(&pending, &recorded).await {
                Ok((resource, decision)) => {
                    comparison.class = classify(legacy, &decision);
                    comparison.resource = Some(resource);
                    comparison.decision = Some(decision);
                }
                Err(reason) => comparison.class = Class::Inconclusive(reason),
            }
        }
        self.report(&comparison);
        if let Some(observer) = self.observer.as_ref() {
            let _ = observer.send(comparison.clone());
        }
        comparison
    }

    async fn decide_for(
        &self,
        pending: &Pending,
        recorded: &Recorded,
    ) -> Result<(ScopeRef, Decision), &'static str> {
        let caller = caller_of(recorded)?;
        let resource = resolve(&self.db, pending.resolver, pending.param.as_deref()).await?;
        let snapshot = tokio::time::timeout(self.snapshot_timeout, self.provider.current())
            .await
            .map_err(|_| "snapshot_timeout")?
            .map_err(|_| "snapshot_unavailable")?;
        let ctx = RequestContext::new(pending.client_ip, pending.now);
        let decision = decide(&snapshot, &caller, pending.permission, resource, &ctx);
        Ok((resource, decision))
    }

    fn report(&self, c: &Comparison) {
        counter!(
            "ak_iam_shadow_comparisons_total",
            "route" => c.route.clone(),
            "permission" => c.permission.id(),
            "class" => c.class.label()
        )
        .increment(1);
        if let Class::Inconclusive(reason) = c.class {
            counter!("ak_iam_shadow_inconclusive_total", "reason" => reason).increment(1);
        }
        if !c.class.is_divergence() {
            return;
        }
        if !self.log_limiter.admit(&c.route, LOG_LIMIT_PER_MINUTE) {
            counter!("ak_iam_shadow_log_suppressed_total").increment(1);
            return;
        }
        let decision = c
            .decision
            .as_ref()
            .and_then(|d| serde_json::to_string(d).ok())
            .unwrap_or_default();
        tracing::warn!(
            target: "iam_shadow",
            route = %c.route,
            method = %c.method,
            permission = %c.permission,
            class = c.class.label(),
            principal_kind = principal_kind(c.principal),
            principal_id = ?c.principal.id(),
            resource = ?c.resource,
            legacy_status = c.legacy_status,
            legacy_class = ?c.legacy,
            decision = %decision,
            "IAM shadow decision diverges from the legacy outcome"
        );
    }
}

fn principal_kind(principal: Principal) -> &'static str {
    match principal {
        Principal::User(_) => "user",
        Principal::ServiceAccount(_) => "service_account",
        Principal::Anonymous => "anonymous",
    }
}

/// Find the resource a declaration's resolver names.
pub async fn resolve(
    db: &PgPool,
    resolver: &Resolver,
    param: Option<&str>,
) -> Result<ScopeRef, &'static str> {
    let uuid = || {
        param
            .ok_or("missing_parameter")?
            .parse::<Uuid>()
            .map_err(|_| "malformed_parameter")
    };
    let found = |row: Result<Option<Uuid>, sqlx::Error>| match row {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err("resource_not_found"),
        Err(_) => Err("resolver_error"),
    };
    match resolver.id {
        "instance" => Ok(ScopeRef::Instance),
        "repo:key" => {
            let key = param.ok_or("missing_parameter")?;
            let row = sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_optional(db)
                .await;
            found(row).map(ScopeRef::Repository)
        }
        "artifact:id" => {
            let id = uuid()?;
            let row = sqlx::query_scalar("SELECT repository_id FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_optional(db)
                .await;
            found(row).map(ScopeRef::Repository)
        }
        "project:id" => uuid().map(ScopeRef::Project),
        "group:id" => uuid().map(ScopeRef::Group),
        _ => Err("unknown_resolver"),
    }
}

/// The middleware. Passes undeclared routes through untouched; for a declared
/// one it records the legacy path, returns the response unchanged, and only
/// then starts the comparison.
pub async fn iam_shadow_middleware(
    State(shadow): State<Arc<IamShadow>>,
    matched: Option<MatchedPath>,
    params: Option<RawPathParams>,
    request: Request,
    next: Next,
) -> Response {
    let pending = matched.and_then(|matched| {
        let params: Vec<(&str, &str)> = params.iter().flat_map(|p| p.iter()).collect();
        shadow.capture(request.method().as_str(), matched.as_str(), &params)
    });
    let Some(pending) = pending else {
        return next.run(request).await;
    };
    let (response, recorded) = shadow_marker::scope(next.run(request)).await;
    shadow.spawn_comparison(pending, response.status(), recorded);
    response
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::authz::shadow_marker::RecordedPrincipal;
    use crate::services::iam_decision::provider::BuildFn;
    use crate::services::iam_decision::snapshot::PolicySnapshot;
    use crate::services::iam_decision::{Grant, RefusalClass, Unavailability};
    use axum::body::Body;
    use axum::http::{HeaderMap, Request as HttpRequest};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn permit() -> Decision {
        Decision::Permit {
            grant: Grant::Baseline {
                visibility: crate::models::repository::RepositoryVisibility::Public,
            },
        }
    }

    fn refuse() -> Decision {
        Decision::Refuse {
            refusal: RefusalClass::NotFound,
        }
    }

    fn unavailable() -> Decision {
        Decision::Unavailable {
            reason: Unavailability::UnknownResource,
        }
    }

    #[test]
    fn legacy_outcomes_follow_the_final_response() {
        use LegacyOutcome::*;
        let cases = [
            (StatusCode::OK, false, Permit),
            (StatusCode::NO_CONTENT, false, Permit),
            (StatusCode::BAD_REQUEST, false, Permit),
            (StatusCode::UNAUTHORIZED, false, Refuse),
            (StatusCode::FORBIDDEN, false, Refuse),
            (StatusCode::NOT_FOUND, true, Refuse),
            (StatusCode::NOT_FOUND, false, Unknown),
            (StatusCode::TOO_MANY_REQUESTS, false, Unknown),
            (StatusCode::INTERNAL_SERVER_ERROR, false, Unknown),
            (StatusCode::SERVICE_UNAVAILABLE, true, Unknown),
            // A list that hid some rows still answered.
            (StatusCode::OK, true, Permit),
        ];
        for (status, marked, expected) in cases {
            assert_eq!(
                legacy_outcome(status, marked),
                expected,
                "{status} {marked}"
            );
        }
    }

    #[test]
    fn every_legacy_and_decision_pair_has_one_class() {
        use LegacyOutcome::*;
        let cases = [
            (Permit, permit(), Class::Agree),
            (Permit, refuse(), Class::NewStricter),
            (Permit, unavailable(), Class::NewUnavailable),
            (Refuse, permit(), Class::NewWider),
            (Refuse, refuse(), Class::Agree),
            (Refuse, unavailable(), Class::NewUnavailable),
            (Unknown, permit(), Class::Inconclusive("legacy_unknown")),
            (Unknown, refuse(), Class::Inconclusive("legacy_unknown")),
            (Unknown, unavailable(), Class::NewUnavailable),
        ];
        for (legacy, decision, expected) in cases {
            assert_eq!(
                classify(legacy, &decision),
                expected,
                "{legacy:?} {decision:?}"
            );
        }
        let divergent: Vec<_> = [
            Class::Agree,
            Class::NewStricter,
            Class::NewWider,
            Class::NewUnavailable,
            Class::Inconclusive("x"),
        ]
        .into_iter()
        .filter(|c| c.is_divergence())
        .map(Class::label)
        .collect();
        assert_eq!(divergent, ["new_stricter", "new_wider", "new_unavailable"]);
    }

    fn recorded(principal: Option<RecordedPrincipal>, api_token: Option<Uuid>) -> Recorded {
        Recorded {
            hidden_refusal: false,
            principal,
            api_token,
        }
    }

    fn principal(
        is_service_account: bool,
        is_api_token: bool,
        restricted: bool,
    ) -> RecordedPrincipal {
        RecordedPrincipal {
            user_id: Uuid::from_u128(7),
            is_service_account,
            is_api_token,
            restricted,
        }
    }

    #[test]
    fn callers_are_mapped_from_what_auth_recorded() {
        let id = Uuid::from_u128(7);
        let token = Uuid::from_u128(9);
        assert_eq!(caller_of(&recorded(None, None)), Ok(Caller::anonymous()));
        assert_eq!(
            caller_of(&recorded(Some(principal(false, false, false)), None)),
            Ok(Caller::session(Principal::User(id)))
        );
        assert_eq!(
            caller_of(&recorded(Some(principal(true, false, false)), None)),
            Ok(Caller::session(Principal::ServiceAccount(id)))
        );
        assert_eq!(
            caller_of(&recorded(Some(principal(true, true, true)), Some(token))),
            Ok(Caller::with_credential(
                Principal::ServiceAccount(id),
                CredentialRef::Token(token)
            ))
        );
        // A token whose id was not recorded, and a restricted JWT, are not
        // decided without their ceiling.
        assert_eq!(
            caller_of(&recorded(Some(principal(false, true, false)), None)),
            Err("unattributed_credential")
        );
        assert_eq!(
            caller_of(&recorded(Some(principal(false, false, true)), None)),
            Err("unattributed_credential")
        );
    }

    #[test]
    fn the_divergence_log_is_limited_per_route() {
        let limiter = LogLimiter::default();
        for _ in 0..LOG_LIMIT_PER_MINUTE {
            assert!(limiter.admit("/a", LOG_LIMIT_PER_MINUTE));
        }
        assert!(!limiter.admit("/a", LOG_LIMIT_PER_MINUTE));
        assert!(limiter.admit("/b", LOG_LIMIT_PER_MINUTE));
    }

    // -- the layer over stub handlers ---------------------------------------

    const STUB: &str = "/api/v1/stub/:case";

    fn stub_registry() -> RouteRegistry {
        let op = serde_json::json!({
            "x-required-permission": "user.read",
            "x-resource": "instance",
        });
        RouteRegistry::from_operations([("get", "/api/v1/stub/{case}", &op)]).unwrap()
    }

    fn snapshot_build(gate: Arc<Semaphore>) -> BuildFn {
        Arc::new(move || {
            let gate = gate.clone();
            Box::pin(async move {
                let _held = gate.acquire().await.unwrap();
                Ok(PolicySnapshot::default())
            })
        })
    }

    fn shadow_with(gate: Arc<Semaphore>) -> IamShadow {
        IamShadow::new(
            stub_registry(),
            Arc::new(SnapshotProvider::new(snapshot_build(gate))),
            crate::api::handlers::test_db_helpers::lazy_pool(),
        )
    }

    async fn stub(axum::extract::Path(case): axum::extract::Path<String>) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert("x-stub", "1".parse().unwrap());
        match case.as_str() {
            "permit" => (headers, "permitted").into_response(),
            "forbidden" => (StatusCode::FORBIDDEN, headers, "no").into_response(),
            "hidden" => {
                shadow_marker::note_hidden_refusal();
                (StatusCode::NOT_FOUND, headers, "Repository not found").into_response()
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, headers, "boom").into_response(),
        }
    }

    fn app(shadow: Option<Arc<IamShadow>>) -> Router {
        let inner = Router::new()
            .route("/stub/:case", get(stub))
            .route("/plain", get(|| async { "plain" }));
        let inner = match shadow {
            Some(shadow) => inner.layer(axum::middleware::from_fn_with_state(
                shadow,
                iam_shadow_middleware,
            )),
            None => inner,
        };
        Router::new().nest(API_V1_PREFIX, inner)
    }

    #[allow(clippy::disallowed_methods)] // STREAMING-EXEMPT: test reads a small, bounded stub body
    async fn call(app: &Router, uri: &str) -> (StatusCode, HeaderMap, bytes::Bytes) {
        let response = app
            .clone()
            .oneshot(HttpRequest::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, parts.headers, body)
    }

    async fn next_comparison(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Comparison>,
    ) -> Comparison {
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("a comparison")
            .expect("observer open")
    }

    #[tokio::test]
    async fn responses_are_identical_with_the_layer_on_and_off() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let shadow = Arc::new(shadow_with(Arc::new(Semaphore::new(1))).with_observer(tx));
        let on = app(Some(shadow));
        let off = app(None);
        let expected = [
            ("permit", LegacyOutcome::Permit),
            ("forbidden", LegacyOutcome::Refuse),
            ("hidden", LegacyOutcome::Refuse),
            ("error", LegacyOutcome::Unknown),
        ];
        for (case, legacy) in expected {
            let uri = format!("/api/v1/stub/{case}");
            assert_eq!(call(&on, &uri).await, call(&off, &uri).await, "{case}");
            let c = next_comparison(&mut rx).await;
            assert_eq!(c.route, STUB);
            assert_eq!(c.method, "GET");
            assert_eq!(c.permission, Permission::UserRead);
            assert_eq!(c.legacy, legacy, "{case}");
            assert_eq!(c.principal, Principal::Anonymous);
        }
        // An undeclared route is passed through and never compared: the next
        // comparison seen is the declared request sent after it.
        assert_eq!(
            call(&on, "/api/v1/plain").await,
            call(&off, "/api/v1/plain").await
        );
        call(&on, "/api/v1/stub/permit").await;
        assert_eq!(next_comparison(&mut rx).await.route, STUB);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_blocked_snapshot_build_does_not_delay_the_response() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        // A gate with no permits: every build blocks.
        let shadow = shadow_with(Arc::new(Semaphore::new(0)))
            .with_limits(SHADOW_PERMITS, Duration::from_millis(200))
            .with_observer(tx);
        let on = app(Some(Arc::new(shadow)));
        let (status, _, body) =
            tokio::time::timeout(Duration::from_secs(2), call(&on, "/api/v1/stub/permit"))
                .await
                .expect("the response does not wait for the snapshot");
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"permitted"[..]));
        let c = next_comparison(&mut rx).await;
        assert_eq!(c.class, Class::Inconclusive("snapshot_timeout"));
    }

    #[tokio::test]
    async fn with_no_free_permit_the_comparison_is_dropped() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let shadow = shadow_with(Arc::new(Semaphore::new(1)))
            .with_limits(0, SNAPSHOT_TIMEOUT)
            .with_observer(tx);
        let on = app(Some(Arc::new(shadow)));
        assert_eq!(call(&on, "/api/v1/stub/permit").await.0, StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err());
    }

    /// A divergence record for an API-token request names the token by id
    /// only: no credential value, header or body reaches the log.
    #[test]
    fn a_divergence_record_carries_no_secret() {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let secret = "akt_live_secret_value_never_logged";
        let token = Uuid::new_v4();
        let comparison = tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let shadow = shadow_with(Arc::new(Semaphore::new(1)));
                let pending = shadow
                    .capture("GET", "/api/v1/stub/:case", &[("case", secret)])
                    .unwrap();
                shadow
                    .compare(
                        pending,
                        StatusCode::OK,
                        recorded(Some(principal(false, true, true)), Some(token)),
                    )
                    .await
            })
        });
        // The empty snapshot does not know the token: new-unavailable.
        assert_eq!(comparison.class, Class::NewUnavailable);
        let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(log.contains("IAM shadow decision diverges"), "{log}");
        assert!(log.contains("unknown_credential"), "{log}");
        for forbidden in [
            secret,
            "authorization",
            "Authorization",
            "Bearer",
            "permitted",
        ] {
            assert!(!log.contains(forbidden), "{forbidden} in {log}");
        }
    }
}

/// Through the real `/api/v1` router with the layer enabled, on the label
/// routes (the declared module).
#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod end_to_end {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use crate::services::cache_invalidation;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    struct Rig {
        state: SharedState,
        provider: Arc<SnapshotProvider>,
        comparisons: tokio::sync::mpsc::UnboundedReceiver<Comparison>,
        shutdown: tokio_util::sync::CancellationToken,
    }

    impl Rig {
        async fn new(pool: PgPool, storage: &std::path::Path) -> Rig {
            let base = tdh::build_state(pool.clone(), storage.to_str().unwrap());
            let provider = Arc::new(SnapshotProvider::for_database(pool.clone()));
            let (tx, comparisons) = tokio::sync::mpsc::unbounded_channel();
            let registry =
                RouteRegistry::from_api_doc(&crate::api::openapi::build_openapi()).unwrap();
            let shadow = IamShadow::new(registry, provider.clone(), pool.clone()).with_observer(tx);
            let mut state = (*base).clone();
            state.iam_shadow = Some(Arc::new(shadow));
            let state = Arc::new(state);
            let shutdown = tokio_util::sync::CancellationToken::new();
            let _listener = cache_invalidation::start_cache_invalidation_listener(
                pool.clone(),
                cache_invalidation::CacheInvalidationHandles {
                    repo_cache: state.repo_cache.clone(),
                    repo_miss_cache: state.repo_miss_cache.clone(),
                    permission_service: state.permission_service.clone(),
                    npm_packument_cache: None,
                    iam_snapshot: Some(provider.clone()),
                },
                shutdown.clone(),
            )
            .await;
            Rig {
                state,
                provider,
                comparisons,
                shutdown,
            }
        }

        /// Add a label as `credential` and return the status and the
        /// comparison of that request.
        async fn add_label(&mut self, credential: &str, key: &str) -> (StatusCode, Comparison) {
            let app = crate::api::routes::create_router(self.state.clone());
            let request = HttpRequest::post(format!("/api/v1/repositories/{key}/labels/env"))
                .header("authorization", credential)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"prod"}"#))
                .unwrap();
            let (status, _) = tdh::send(app, request).await;
            let comparison = tokio::time::timeout(Duration::from_secs(15), self.comparisons.recv())
                .await
                .expect("a comparison")
                .expect("observer open");
            assert_eq!(
                comparison.route,
                "/api/v1/repositories/:key/labels/:label_key"
            );
            assert_eq!(comparison.permission, Permission::RepositoryLabelManage);
            (status, comparison)
        }
    }

    fn is_refusal(c: &Comparison) -> bool {
        matches!(c.decision, Some(Decision::Refuse { .. }))
    }

    #[tokio::test]
    async fn label_writes_are_compared_and_follow_rule_changes() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (writer, _) = tdh::create_user(&pool).await;
        let (outsider, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_role(&pool, repo, writer, "developer").await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let writer_bearer = tdh::bearer_for(&rig.state, writer).await;
        let outsider_bearer = tdh::bearer_for(&rig.state, outsider).await;

        // An authorized write: both permit.
        let (status, c) = rig.add_label(&writer_bearer, &key).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::Agree),
            "{c:?}"
        );
        assert_eq!(c.principal, Principal::User(writer));
        assert_eq!(c.resource, Some(ScopeRef::Repository(repo)));

        // No access: the hidden 404 is a refusal, and both refuse.
        let (status, c) = rig.add_label(&outsider_bearer, &key).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Refuse, Class::Agree),
            "{c:?}"
        );

        // The legacy rule is deleted behind the API's back; the notification
        // reaches the provider and the next comparison refuses too.
        let generation = rig.provider.generation();
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
            .bind(writer)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while rig.provider.generation() == generation {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the provider is invalidated by the notification");
        let (status, c) = rig.add_label(&writer_bearer, &key).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(is_refusal(&c), "{c:?}");
        assert_eq!(c.class, Class::Agree, "{c:?}");

        rig.shutdown.cancel();
        tdh::cleanup_user(&pool, outsider).await;
        tdh::cleanup(&pool, repo, writer).await;
    }

    #[tokio::test]
    async fn an_api_token_is_decided_with_its_ceiling() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (elsewhere, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (user, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_role(&pool, repo, user, "developer").await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (token, token_id) = auth
            .generate_api_token(user, "shadow", vec!["*".into()], None)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(token_id)
            .bind(elsewhere)
            .execute(&pool)
            .await
            .unwrap();

        // The user may write, the token may not reach this repository.
        let (status, c) = rig.add_label(&format!("Bearer {token}"), &key).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.legacy, LegacyOutcome::Refuse, "{c:?}");
        assert!(is_refusal(&c), "{c:?}");
        assert_eq!(c.class, Class::Agree, "{c:?}");

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(elsewhere)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo, user).await;
    }
}
