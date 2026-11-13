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

use crate::api::authz::catalog::{Permission, Scope};
use crate::api::authz::declaration::{Resolver, RouteRequirement};
use crate::api::authz::registry::{RouteRegistry, API_V1_PREFIX};
use crate::api::authz::shadow_marker::{self, LegacyLevel, Recorded};
use crate::api::handlers::sbom::{classify_cve_history_path, CveHistoryPath};
use crate::api::middleware::client_ip::current_verified_client_ip;
use crate::config::Config;
use crate::services::iam_decision::provider::SnapshotProvider;
use crate::services::iam_decision::{decide, Caller, Decision, Principal, RequestContext};
use crate::services::iam_legacy_projection::{CredentialRef, ScopeRef};

/// The parameter of a resolver whose resource the handler reports from the
/// request body, for any kind (`project:body`, `repository:body`).
pub const BODY_PARAMETER: &str = ":body";
/// The resolver naming a user in the path; the operation is self-service when
/// that user is the caller.
pub const USER_RESOLVER: &str = "user:id";

/// Whether the declaration's resource is the target the handler reports.
fn is_body_resolved(pending: &Pending) -> bool {
    pending.resolver.id.ends_with(BODY_PARAMETER)
}

/// Whether a request is self-service: it names the caller through
/// [`USER_RESOLVER`]. Self-service needs no permission, so it is not compared.
pub fn is_self_service(pending: &Pending, recorded: &Recorded) -> bool {
    pending.resolver.id == USER_RESOLVER
        && recorded.principal.is_some_and(|p| {
            pending
                .param
                .as_deref()
                .and_then(|v| v.parse::<Uuid>().ok())
                == Some(p.user_id)
        })
}

/// What a comparison settled: the legacy outcome, the resource once resolved,
/// and the new decision when the legacy outcome is known.
struct Settled {
    legacy: LegacyOutcome,
    resource: Option<ScopeRef>,
    decision: Option<Result<Decision, &'static str>>,
}

/// The class of a comparison whose legacy outcome is unknown.
fn classify_unknown(legacy: LegacyOutcome) -> Class {
    match legacy {
        LegacyOutcome::Unknown(reason) => Class::Inconclusive(reason),
        _ => Class::Inconclusive("legacy_unknown"),
    }
}

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
    /// A refusal the handler keeps after enforcement (object-level rules,
    /// administrator-only options, a second resource): the route-level
    /// decision did not make it.
    KeptRefusal,
    /// The response does not say whether the declared check passed; the
    /// reason is a fixed label.
    Unknown(&'static str),
}

/// What the response alone settles, before the resource is resolved: a 429
/// or a server error, and a 404 that nothing marked.
pub fn settled_by_status(status: StatusCode, recorded: &Recorded) -> Option<LegacyOutcome> {
    let unmarked = recorded.hidden_refusal.is_none() && recorded.kept_refusal.is_none();
    let settled = status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
        || (status == StatusCode::NOT_FOUND && unmarked);
    settled.then_some(LegacyOutcome::Unknown("legacy_unknown"))
}

/// An unmarked 404 on an instance-resolved declaration after the instance
/// check passed: the instance hides nothing, so the object is missing.
fn missing_after_instance_pass(
    status: StatusCode,
    recorded: &Recorded,
    resource: ScopeRef,
    needed: LegacyLevel,
) -> bool {
    status == StatusCode::NOT_FOUND
        && resource == ScopeRef::Instance
        && recorded.hidden_refusal.is_none()
        && recorded.kept_refusal.is_none()
        && recorded
            .passed_on(ScopeRef::Instance)
            .is_some_and(|level| level.satisfies(needed))
}

/// Classify the legacy response for the declared check on `resource`.
///
/// * A 404 is a refusal only when a hiding helper marked it for `resource`; a
///   mark for another repository is a second resource the declaration does
///   not decide.
/// * A 401, 403 or 404 with a kept refusal recorded is that kept refusal.
/// * Any other 4xx is a permit only when a legacy check at the declared level
///   passed on `resource` before it; otherwise the input or the repository
///   type was rejected before the check ran.
/// * Any mark on a success (a list that filtered out some rows) does not make
///   the request a refusal.
pub fn legacy_outcome(
    status: StatusCode,
    recorded: &Recorded,
    resource: ScopeRef,
    needed: LegacyLevel,
) -> LegacyOutcome {
    if missing_after_instance_pass(status, recorded, resource, needed) {
        return LegacyOutcome::Permit;
    }
    if let Some(settled) = settled_by_status(status, recorded) {
        return settled;
    }
    let repository = match resource {
        ScopeRef::Repository(id) => Some(id),
        _ => None,
    };
    let hidden_here = repository.is_some() && recorded.hidden_refusal == repository;
    let refusal = matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    );
    match status {
        StatusCode::NOT_FOUND if hidden_here => LegacyOutcome::Refuse,
        _ if refusal && recorded.kept_refusal.is_some() => LegacyOutcome::KeptRefusal,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => LegacyOutcome::Refuse,
        StatusCode::NOT_FOUND => LegacyOutcome::Unknown("secondary_resource"),
        s if s.is_client_error() => {
            // An instance administrator passes every legacy check, so an
            // instance pass at `Admin` counts on any resource.
            let passed = recorded
                .passed_on(resource)
                .is_some_and(|level| level.satisfies(needed))
                || recorded.passed_on(ScopeRef::Instance) == Some(LegacyLevel::Admin);
            if passed {
                LegacyOutcome::Permit
            } else {
                LegacyOutcome::Unknown("validation_before_authorization")
            }
        }
        _ => LegacyOutcome::Permit,
    }
}

/// The legacy check a declared permission corresponds to, for telling a 4xx
/// after that check from one before it.
pub fn legacy_level(permission: Permission) -> LegacyLevel {
    use Permission as P;
    match permission {
        p if p.id().ends_with(".read") => LegacyLevel::Read,
        P::ArtifactWrite
        | P::ArtifactAnnotate
        | P::EnvironmentWrite
        | P::ImageBuildCreate
        | P::SecurityScan
        | P::RepositoryLabelManage => LegacyLevel::Write,
        P::ArtifactDelete => LegacyLevel::Delete,
        _ => LegacyLevel::Admin,
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
        (LegacyOutcome::Unknown(reason), _) => Class::Inconclusive(reason),
        (LegacyOutcome::KeptRefusal, Decision::Permit { .. }) => {
            Class::Inconclusive("handler_check")
        }
        (LegacyOutcome::Permit, Decision::Permit { .. })
        | (LegacyOutcome::Refuse | LegacyOutcome::KeptRefusal, Decision::Refuse { .. }) => {
            Class::Agree
        }
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
        let mut comparison = Comparison {
            route: pending.route.clone(),
            method: pending.method.clone(),
            permission: pending.permission,
            principal: principal_of(&recorded),
            resource: None,
            legacy_status: status.as_u16(),
            legacy: LegacyOutcome::Unknown("legacy_unknown"),
            decision: None,
            class: Class::Inconclusive("legacy_unknown"),
        };
        match self.settle(&pending, status, &recorded).await {
            Err(reason) => comparison.class = Class::Inconclusive(reason),
            Ok(Settled {
                legacy,
                resource,
                decision,
            }) => {
                comparison.legacy = legacy;
                comparison.resource = resource;
                comparison.class = match decision {
                    Some(Ok(decision)) => {
                        let class = classify(legacy, &decision);
                        comparison.decision = Some(decision);
                        class
                    }
                    Some(Err(reason)) => Class::Inconclusive(reason),
                    None => classify_unknown(legacy),
                };
            }
        }
        if comparison.class == Class::Inconclusive("handler_check") {
            if let Some(reason) = recorded.kept_refusal {
                counter!("ak_iam_shadow_kept_refusals_total", "reason" => reason).increment(1);
            }
        }
        self.report(&comparison);
        if let Some(observer) = self.observer.as_ref() {
            let _ = observer.send(comparison.clone());
        }
        comparison
    }

    /// The legacy outcome, the resource and, when the legacy outcome is
    /// known, the new decision. `Err` when the resource cannot be found.
    async fn settle(
        &self,
        pending: &Pending,
        status: StatusCode,
        recorded: &Recorded,
    ) -> Result<Settled, &'static str> {
        if is_self_service(pending, recorded) {
            return Err("self_service");
        }
        // Without a reported target there is nothing to decide on, whatever
        // the response says.
        if is_body_resolved(pending) && recorded.target.is_none() {
            return Err("target_not_reported");
        }
        // The instance needs no lookup, so its status is settled with the
        // resource known (`legacy_outcome`), where a pass can count.
        let looked_up = pending.resolver.scope != Scope::Instance;
        if let Some(legacy) = settled_by_status(status, recorded).filter(|_| looked_up) {
            return Ok(Settled {
                legacy,
                resource: None,
                decision: None,
            });
        }
        let resource = self.resource_for(pending, recorded).await?;
        let legacy = legacy_outcome(status, recorded, resource, legacy_level(pending.permission));
        let decision = if matches!(legacy, LegacyOutcome::Unknown(_)) {
            None
        } else {
            Some(self.decide_on(pending, recorded, resource).await)
        };
        Ok(Settled {
            legacy,
            resource: Some(resource),
            decision,
        })
    }

    /// The resource a declaration names: from the path, or for a
    /// body-resolved declaration the target the handler reported.
    async fn resource_for(
        &self,
        pending: &Pending,
        recorded: &Recorded,
    ) -> Result<ScopeRef, &'static str> {
        if is_body_resolved(pending) {
            return recorded.target.ok_or("target_not_reported");
        }
        resolve(&self.db, pending.resolver, pending.param.as_deref()).await
    }

    async fn decide_on(
        &self,
        pending: &Pending,
        recorded: &Recorded,
        resource: ScopeRef,
    ) -> Result<Decision, &'static str> {
        let caller = caller_of(recorded)?;
        let snapshot = tokio::time::timeout(self.snapshot_timeout, self.provider.current())
            .await
            .map_err(|_| "snapshot_timeout")?
            .map_err(|_| "snapshot_unavailable")?;
        let ctx = RequestContext::new(pending.client_ip, pending.now);
        Ok(decide(
            &snapshot,
            &caller,
            pending.permission,
            resource,
            &ctx,
        ))
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
    // The repository holding the object an id names, by one query.
    let repository_of = |sql: &'static str| async move {
        let id = uuid()?;
        let row = sqlx::query_scalar(sql).bind(id).fetch_optional(db).await;
        found(row).map(ScopeRef::Repository)
    };
    let (kind, _) = resolver.id.split_once(':').unwrap_or((resolver.id, ""));
    match kind {
        "instance" => Ok(ScopeRef::Instance),
        "repo" => {
            let key = param.ok_or("missing_parameter")?;
            let row = sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
                .bind(key)
                .fetch_optional(db)
                .await;
            found(row).map(ScopeRef::Repository)
        }
        "repository" => repository_of("SELECT id FROM repositories WHERE id = $1").await,
        "artifact" => repository_of(ARTIFACT_REPOSITORY).await,
        "scan" => repository_of("SELECT repository_id FROM scan_results WHERE id = $1").await,
        "finding" => {
            repository_of(
                "SELECT s.repository_id FROM scan_findings f \
                 JOIN scan_results s ON s.id = f.scan_result_id WHERE f.id = $1",
            )
            .await
        }
        "sbom" => repository_of("SELECT repository_id FROM sbom_documents WHERE id = $1").await,
        "cve_entry" => {
            repository_of(
                "SELECT a.repository_id FROM cve_history h \
                 JOIN artifacts a ON a.id = h.artifact_id WHERE h.id = $1",
            )
            .await
        }
        "quality_check" => {
            repository_of("SELECT repository_id FROM quality_check_results WHERE id = $1").await
        }
        "quality_issue" => {
            repository_of(
                "SELECT c.repository_id FROM quality_check_issues i \
                 JOIN quality_check_results c ON c.id = i.check_result_id WHERE i.id = $1",
            )
            .await
        }
        // An acknowledgement or a webhook with no repository applies to
        // every one.
        "acknowledgement" => repository_or_instance(db, uuid()?, ACKNOWLEDGEMENT_REPOSITORY).await,
        "webhook" => repository_or_instance(db, uuid()?, WEBHOOK_REPOSITORY).await,
        // CVE history by artifact or by CVE id, as the handler reads the path.
        "cve_subject" => {
            let raw = param.ok_or("missing_parameter")?;
            match classify_cve_history_path(raw) {
                CveHistoryPath::Artifact(id) => {
                    let row = sqlx::query_scalar(ARTIFACT_REPOSITORY)
                        .bind(id)
                        .fetch_optional(db)
                        .await;
                    found(row).map(ScopeRef::Repository)
                }
                CveHistoryPath::Cve(_) => Ok(ScopeRef::Instance),
                CveHistoryPath::Invalid => Err("malformed_parameter"),
            }
        }
        "project" => uuid().map(ScopeRef::Project),
        "user" => uuid().map(|_| ScopeRef::Instance),
        "group" => uuid().map(ScopeRef::Group),
        _ => Err("unknown_resolver"),
    }
}

const ARTIFACT_REPOSITORY: &str = "SELECT repository_id FROM artifacts WHERE id = $1";
const ACKNOWLEDGEMENT_REPOSITORY: &str =
    "SELECT repository_id FROM finding_acknowledgements WHERE id = $1";
const WEBHOOK_REPOSITORY: &str = "SELECT repository_id FROM webhooks WHERE id = $1";

/// The repository in a nullable `repository_id` column, or the instance when
/// it is null.
async fn repository_or_instance(
    db: &PgPool,
    id: Uuid,
    sql: &'static str,
) -> Result<ScopeRef, &'static str> {
    let row: Result<Option<Option<Uuid>>, sqlx::Error> =
        sqlx::query_scalar(sql).bind(id).fetch_optional(db).await;
    match row {
        Ok(Some(Some(repository))) => Ok(ScopeRef::Repository(repository)),
        Ok(Some(None)) => Ok(ScopeRef::Instance),
        Ok(None) => Err("resource_not_found"),
        Err(_) => Err("resolver_error"),
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
    fn legacy_outcomes_follow_the_final_response_and_the_recorder() {
        use LegacyLevel as L;
        use LegacyOutcome::*;
        let (repo, other) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let here = ScopeRef::Repository(repo);
        let none = Recorded::default();
        let hidden = |id| Recorded {
            hidden_refusal: Some(id),
            ..Recorded::default()
        };
        let kept = Recorded {
            kept_refusal: Some("token_owner"),
            ..Recorded::default()
        };
        let passed_at = |resource, level| Recorded {
            passed: vec![(resource, level)],
            ..Recorded::default()
        };
        let passed = |id, level| passed_at(ScopeRef::Repository(id), level);
        let project = ScopeRef::Project(repo);
        let cases = [
            (StatusCode::OK, none.clone(), here, L::Admin, Permit),
            (StatusCode::NO_CONTENT, none.clone(), here, L::Write, Permit),
            // A list that hid some rows still answered.
            (StatusCode::OK, hidden(repo), here, L::Read, Permit),
            (
                StatusCode::UNAUTHORIZED,
                none.clone(),
                here,
                L::Read,
                Refuse,
            ),
            (StatusCode::FORBIDDEN, none.clone(), here, L::Admin, Refuse),
            (StatusCode::NOT_FOUND, hidden(repo), here, L::Read, Refuse),
            // A hidden refusal of the declared repository outranks a kept one.
            (
                StatusCode::NOT_FOUND,
                Recorded {
                    hidden_refusal: Some(repo),
                    kept_refusal: Some("x"),
                    ..Recorded::default()
                },
                here,
                L::Read,
                Refuse,
            ),
            (
                StatusCode::NOT_FOUND,
                hidden(other),
                here,
                L::Admin,
                Unknown("secondary_resource"),
            ),
            (
                StatusCode::NOT_FOUND,
                hidden(repo),
                ScopeRef::Instance,
                L::Admin,
                Unknown("secondary_resource"),
            ),
            (
                StatusCode::NOT_FOUND,
                none.clone(),
                here,
                L::Read,
                Unknown("legacy_unknown"),
            ),
            // After the instance check, a 404 on the instance is a missing
            // object; without the pass, or on another resource, it is not.
            (
                StatusCode::NOT_FOUND,
                passed_at(ScopeRef::Instance, L::Admin),
                ScopeRef::Instance,
                L::Admin,
                Permit,
            ),
            (
                StatusCode::NOT_FOUND,
                none.clone(),
                ScopeRef::Instance,
                L::Admin,
                Unknown("legacy_unknown"),
            ),
            (
                StatusCode::NOT_FOUND,
                passed_at(ScopeRef::Instance, L::Admin),
                here,
                L::Read,
                Unknown("legacy_unknown"),
            ),
            (
                StatusCode::NOT_FOUND,
                passed_at(ScopeRef::Instance, L::Admin),
                project,
                L::Admin,
                Unknown("legacy_unknown"),
            ),
            (
                StatusCode::FORBIDDEN,
                kept.clone(),
                here,
                L::Admin,
                KeptRefusal,
            ),
            (
                StatusCode::NOT_FOUND,
                kept.clone(),
                here,
                L::Read,
                KeptRefusal,
            ),
            (
                StatusCode::CONFLICT,
                kept.clone(),
                here,
                L::Delete,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                hidden(repo),
                here,
                L::Read,
                Unknown("legacy_unknown"),
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                kept,
                here,
                L::Read,
                Unknown("legacy_unknown"),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                hidden(repo),
                here,
                L::Read,
                Unknown("legacy_unknown"),
            ),
            // A 4xx after the declared check passed is a permit; before it, or
            // after a weaker one, or on another repository, it says nothing.
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Admin),
                here,
                L::Admin,
                Permit,
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Admin),
                here,
                L::Write,
                Permit,
            ),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                passed(repo, L::Write),
                here,
                L::Write,
                Permit,
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Write),
                here,
                L::Read,
                Permit,
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Read),
                here,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Delete),
                here,
                L::Write,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(other, L::Admin),
                here,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
            // The same holds for a project, a group or the instance.
            (
                StatusCode::CONFLICT,
                passed_at(project, L::Admin),
                project,
                L::Admin,
                Permit,
            ),
            (
                StatusCode::BAD_REQUEST,
                passed_at(ScopeRef::Project(other), L::Admin),
                project,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::BAD_REQUEST,
                passed(repo, L::Admin),
                project,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::CONFLICT,
                passed_at(ScopeRef::Group(repo), L::Admin),
                ScopeRef::Group(repo),
                L::Admin,
                Permit,
            ),
            (
                StatusCode::CONFLICT,
                passed_at(ScopeRef::Instance, L::Admin),
                ScopeRef::Instance,
                L::Admin,
                Permit,
            ),
            (
                StatusCode::BAD_REQUEST,
                none.clone(),
                ScopeRef::Instance,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
            // An instance administrator passes every check: a client error
            // after that pass is a permit on any resource.
            (
                StatusCode::CONFLICT,
                passed_at(ScopeRef::Instance, L::Admin),
                here,
                L::Admin,
                Permit,
            ),
            (
                StatusCode::CONFLICT,
                passed_at(ScopeRef::Instance, L::Read),
                here,
                L::Read,
                Unknown("validation_before_authorization"),
            ),
            (
                StatusCode::CONFLICT,
                none.clone(),
                here,
                L::Admin,
                Unknown("validation_before_authorization"),
            ),
        ];
        for (status, recorded, resource, needed, expected) in cases {
            assert_eq!(
                legacy_outcome(status, &recorded, resource, needed),
                expected,
                "{status} {recorded:?} {resource:?} {needed:?}"
            );
        }
        assert_eq!(
            settled_by_status(StatusCode::NOT_FOUND, &none),
            Some(Unknown("legacy_unknown"))
        );
        assert_eq!(
            settled_by_status(StatusCode::NOT_FOUND, &hidden(repo)),
            None
        );
        assert_eq!(settled_by_status(StatusCode::OK, &none), None);
    }

    #[test]
    fn every_catalog_permission_has_a_legacy_level() {
        use LegacyLevel as L;
        for p in Permission::ALL {
            let level = legacy_level(*p);
            if p.id().ends_with(".read") {
                assert_eq!(level, L::Read, "{p}");
            }
        }
        assert_eq!(legacy_level(Permission::ArtifactWrite), L::Write);
        assert_eq!(legacy_level(Permission::EnvironmentWrite), L::Write);
        assert_eq!(legacy_level(Permission::ArtifactDelete), L::Delete);
        assert_eq!(legacy_level(Permission::RepositoryUpdate), L::Admin);
        assert_eq!(legacy_level(Permission::RepositoryTokenManage), L::Admin);
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
            (
                Unknown("legacy_unknown"),
                permit(),
                Class::Inconclusive("legacy_unknown"),
            ),
            (
                Unknown("secondary_resource"),
                refuse(),
                Class::Inconclusive("secondary_resource"),
            ),
            (
                Unknown("legacy_unknown"),
                unavailable(),
                Class::NewUnavailable,
            ),
            (KeptRefusal, permit(), Class::Inconclusive("handler_check")),
            (KeptRefusal, refuse(), Class::Agree),
            (KeptRefusal, unavailable(), Class::NewUnavailable),
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
            principal,
            api_token,
            ..Recorded::default()
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

    #[tokio::test]
    async fn a_named_user_is_the_instance_unless_it_is_the_caller() {
        let shadow = shadow_with(Arc::new(Semaphore::new(1)));
        let caller = principal(false, false, false);
        let pending = |param: &str| Pending {
            method: "GET".into(),
            route: "/api/v1/users/{id}".into(),
            permission: Permission::UserRead,
            resolver: Resolver::lookup(USER_RESOLVER).unwrap(),
            param: Some(param.into()),
            client_ip: None,
            now: Utc::now(),
        };
        let compare = |param: String| {
            let shadow = &shadow;
            async move {
                shadow
                    .compare(
                        pending(&param),
                        StatusCode::FORBIDDEN,
                        recorded(Some(caller), None),
                    )
                    .await
            }
        };

        let own = compare(caller.user_id.to_string()).await;
        assert_eq!(own.class, Class::Inconclusive("self_service"));
        assert!(!own.class.is_divergence());

        let other = compare(Uuid::from_u128(8).to_string()).await;
        assert_eq!(other.resource, Some(ScopeRef::Instance));
        assert_eq!(other.class, Class::Agree);

        let malformed = compare("me".into()).await;
        assert_eq!(malformed.class, Class::Inconclusive("malformed_parameter"));

        // Anonymous names nobody: never self-service.
        let anonymous = shadow
            .compare(
                pending(&caller.user_id.to_string()),
                StatusCode::UNAUTHORIZED,
                Recorded::default(),
            )
            .await;
        assert_eq!(anonymous.class, Class::Agree);
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

    const STUB_BODY: &str = "/api/v1/stub-body/:case";
    const STUB_PROJECT: Uuid = Uuid::from_u128(0x5eed);

    fn stub_registry() -> RouteRegistry {
        let op = serde_json::json!({
            "x-required-permission": "user.read",
            "x-resource": "instance",
        });
        let body = serde_json::json!({
            "x-required-permission": "repository.create",
            "x-resource": "project:body",
        });
        RouteRegistry::from_operations([
            ("get", "/api/v1/stub/{case}", &op),
            ("get", "/api/v1/stub-body/{case}", &body),
        ])
        .unwrap()
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
                shadow_marker::note_hidden_refusal(Uuid::from_u128(1));
                (StatusCode::NOT_FOUND, headers, "Repository not found").into_response()
            }
            "kept" => {
                shadow_marker::note_kept_refusal("stub_rule");
                (StatusCode::FORBIDDEN, headers, "no").into_response()
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, headers, "boom").into_response(),
        }
    }

    /// A handler of a body-resolved declaration: reports the project, the
    /// instance, or (rejecting the body first) nothing.
    async fn stub_body(axum::extract::Path(case): axum::extract::Path<String>) -> Response {
        match case.as_str() {
            "project" => {
                shadow_marker::note_target(ScopeRef::Project(STUB_PROJECT));
                (StatusCode::CREATED, "created").into_response()
            }
            "instance" => {
                shadow_marker::note_target(ScopeRef::Instance);
                (StatusCode::FORBIDDEN, "no").into_response()
            }
            _ => (StatusCode::BAD_REQUEST, "malformed").into_response(),
        }
    }

    fn app(shadow: Option<Arc<IamShadow>>) -> Router {
        let inner = Router::new()
            .route("/stub/:case", get(stub))
            .route("/stub-body/:case", get(stub_body))
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
        // The stub declares an instance resource, so a hidden refusal of a
        // repository is a second resource.
        let expected = [
            ("permit", LegacyOutcome::Permit),
            ("forbidden", LegacyOutcome::Refuse),
            ("hidden", LegacyOutcome::Unknown("secondary_resource")),
            ("kept", LegacyOutcome::KeptRefusal),
            ("error", LegacyOutcome::Unknown("legacy_unknown")),
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
    async fn a_body_resolved_declaration_uses_the_reported_target() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let shadow = Arc::new(shadow_with(Arc::new(Semaphore::new(1))).with_observer(tx));
        let on = app(Some(shadow));
        let off = app(None);
        let expected = [
            ("project", Some(ScopeRef::Project(STUB_PROJECT))),
            ("instance", Some(ScopeRef::Instance)),
            ("none", None),
        ];
        for (case, resource) in expected {
            let uri = format!("/api/v1/stub-body/{case}");
            assert_eq!(call(&on, &uri).await, call(&off, &uri).await, "{case}");
            let c = next_comparison(&mut rx).await;
            assert_eq!(c.route, STUB_BODY);
            assert_eq!(c.permission, Permission::RepositoryCreate);
            assert_eq!(c.resource, resource, "{case}");
            if resource.is_none() {
                assert_eq!(c.class, Class::Inconclusive("target_not_reported"));
            } else {
                assert!(c.decision.is_some(), "{case}: {c:?}");
            }
        }
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
            Rig::over(
                pool.clone(),
                tdh::build_state(pool, storage.to_str().unwrap()),
            )
            .await
        }

        /// The layer over an existing state.
        async fn over(pool: PgPool, base: SharedState) -> Rig {
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

        /// Send `request` through the real router as `credential` (none for
        /// anonymous) and return the status and the comparison of that request.
        async fn call(
            &mut self,
            credential: Option<&str>,
            mut request: HttpRequest<Body>,
        ) -> (StatusCode, Comparison) {
            if let Some(credential) = credential {
                request
                    .headers_mut()
                    .insert("authorization", credential.parse().unwrap());
            }
            let app = crate::api::routes::create_router(self.state.clone());
            let (status, _) = tdh::send(app, request).await;
            let comparison = tokio::time::timeout(Duration::from_secs(15), self.comparisons.recv())
                .await
                .expect("a comparison")
                .expect("observer open");
            (status, comparison)
        }
    }

    fn json_request(method: &str, uri: String, body: serde_json::Value) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn empty_request(method: &str, uri: String) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
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

    async fn delete_repository(pool: &PgPool, id: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn artifact_reads_and_writes_agree() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::publish_repo(&pool, repo).await;
        let (developer, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_role(&pool, repo, developer, "developer").await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let bearer = tdh::bearer_for(&rig.state, developer).await;

        // A developer uploads: both permit.
        let upload = HttpRequest::put(format!("/api/v1/repositories/{key}/artifacts/a/b.txt"))
            .body(Body::from("payload"))
            .unwrap();
        let (status, c) = rig.call(Some(&bearer), upload).await;
        assert!(status.is_success(), "{status}");
        assert_eq!(c.permission, Permission::ArtifactWrite);
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::Agree),
            "{c:?}"
        );

        // The same developer may not reconfigure the repository: both refuse.
        let patch = json_request(
            "PATCH",
            format!("/api/v1/repositories/{key}"),
            serde_json::json!({"description": "changed"}),
        );
        let (status, c) = rig.call(Some(&bearer), patch).await;
        assert!(status.is_client_error(), "{status}");
        assert_eq!(c.permission, Permission::RepositoryUpdate);
        assert!(is_refusal(&c), "{c:?}");
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Refuse, Class::Agree),
            "{c:?}"
        );

        // Anyone reads an artifact of a public repository: both permit.
        let artifact = tdh::artifact_id_at(&pool, repo, "a/b.txt").await;
        let (status, c) = rig
            .call(
                None,
                empty_request("GET", format!("/api/v1/artifacts/{artifact}")),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.principal, Principal::Anonymous);
        assert_eq!(c.resource, Some(ScopeRef::Repository(repo)));
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::Agree),
            "{c:?}"
        );

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo, developer).await;
    }

    #[tokio::test]
    async fn a_project_administrator_creates_a_repository_in_the_project() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (_, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (admin, _) = tdh::create_user(&pool).await;
        let project_key = format!("prj-shadow-{}", Uuid::new_v4().simple());
        let project: Uuid =
            sqlx::query_scalar("INSERT INTO projects (key, name) VALUES ($1, $1) RETURNING id")
                .bind(&project_key)
                .fetch_one(&pool)
                .await
                .unwrap();
        tdh::grant_permission(&pool, "user", admin, "project", project, &["admin"]).await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let bearer = tdh::bearer_for(&rig.state, admin).await;

        let key = format!("shadow-create-{}", Uuid::new_v4().simple());
        let create = json_request(
            "POST",
            "/api/v1/repositories".to_string(),
            serde_json::json!({
                "key": key, "name": key, "format": "generic",
                "repo_type": "local", "project_id": project,
            }),
        );
        let (status, c) = rig.call(Some(&bearer), create).await;
        assert!(status.is_success(), "{status}");
        assert_eq!(c.permission, Permission::RepositoryCreate);
        assert_eq!(c.resource, Some(ScopeRef::Project(project)));
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::Agree),
            "{c:?}"
        );

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM repositories WHERE key = $1")
            .bind(&key)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(project)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, admin).await;
    }

    #[tokio::test]
    async fn project_and_group_management_is_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (manager, _) = tdh::create_user(&pool).await;
        let (member, _) = tdh::create_user(&pool).await;
        let (instance_admin, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(instance_admin)
            .execute(&pool)
            .await
            .unwrap();
        let mine = new_project(&pool).await;
        let theirs = new_project(&pool).await;
        let mine_key: String = sqlx::query_scalar("SELECT key FROM projects WHERE id = $1")
            .bind(mine)
            .fetch_one(&pool)
            .await
            .unwrap();
        tdh::grant_permission(&pool, "user", manager, "project", mine, &["admin"]).await;
        let group = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id, name, external_source) VALUES ($1, $2, 'ldap')")
            .bind(group)
            .bind(format!("shadow-ldap-{group}"))
            .execute(&pool)
            .await
            .unwrap();
        tdh::grant_permission(&pool, "user", manager, "group", group, &["admin"]).await;
        tdh::grant_permission(
            &pool,
            "user",
            manager,
            crate::services::permission_service::SYSTEM_TARGET_TYPE,
            crate::services::permission_service::SYSTEM_SENTINEL_ID,
            &["admin"],
        )
        .await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let bearer = tdh::bearer_for(&rig.state, manager).await;
        let admin_bearer = tdh::bearer_for(&rig.state, instance_admin).await;
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (write_token, write_id) = auth
            .generate_api_token(manager, "shadow-write", vec!["*".into()], None)
            .await
            .unwrap();
        // A bare `write` scope can no longer be minted; tokens holding one
        // predate scope validation, so the row is rewritten to match them.
        sqlx::query("UPDATE api_tokens SET scopes = ARRAY['write'] WHERE id = $1")
            .bind(write_id)
            .execute(&pool)
            .await
            .unwrap();
        let (scoped_token, scoped_id) = auth
            .generate_api_token(manager, "shadow-scoped", vec!["*".into()], None)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(scoped_id)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        let add_member = || {
            json_request(
                "POST",
                format!("/api/v1/projects/{mine}/members"),
                serde_json::json!({
                    "principal_type": "user", "principal_id": member, "actions": ["read"],
                }),
            )
        };
        let agrees = |c: &Comparison, legacy: LegacyOutcome| {
            assert_eq!((c.legacy, c.class), (legacy, Class::Agree), "{c:?}");
        };

        // The project administrator manages their own project.
        let (status, c) = rig
            .call(
                Some(&bearer),
                empty_request("GET", format!("/api/v1/projects/{mine}")),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::ProjectRead);
        assert_eq!(c.resource, Some(ScopeRef::Project(mine)));
        agrees(&c, LegacyOutcome::Permit);
        let rename = json_request(
            "PUT",
            format!("/api/v1/projects/{mine}"),
            serde_json::json!({"name": "renamed"}),
        );
        let (status, c) = rig.call(Some(&bearer), rename).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::ProjectUpdate);
        agrees(&c, LegacyOutcome::Permit);
        let (status, c) = rig.call(Some(&bearer), add_member()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::IamManage);
        agrees(&c, LegacyOutcome::Permit);

        // ... and not another project.
        let (status, c) = rig
            .call(
                Some(&bearer),
                empty_request("GET", format!("/api/v1/projects/{theirs}")),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(is_refusal(&c), "{c:?}");
        agrees(&c, LegacyOutcome::Refuse);

        // A duplicate project key after the instance check passed.
        let duplicate = json_request(
            "POST",
            "/api/v1/projects".to_string(),
            serde_json::json!({"key": mine_key, "name": "dup"}),
        );
        let (status, c) = rig.call(Some(&admin_bearer), duplicate).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(c.permission, Permission::ProjectCreate);
        agrees(&c, LegacyOutcome::Permit);

        // A member change on an identity-provider group after the group check.
        let (status, c) = rig
            .call(
                Some(&bearer),
                json_request(
                    "POST",
                    format!("/api/v1/groups/{group}/members"),
                    serde_json::json!({"user_ids": [member]}),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(c.permission, Permission::GroupManage);
        assert_eq!(c.resource, Some(ScopeRef::Group(group)));
        agrees(&c, LegacyOutcome::Permit);

        // The sentinel holder creates a group.
        let created = format!("shadow-created-{}", Uuid::new_v4().simple());
        let (status, c) = rig
            .call(
                Some(&bearer),
                json_request(
                    "POST",
                    "/api/v1/groups".to_string(),
                    serde_json::json!({"name": created}),
                ),
            )
            .await;
        assert!(status.is_success(), "{status}");
        assert_eq!(c.permission, Permission::GroupCreate);
        agrees(&c, LegacyOutcome::Permit);

        // The enumerated tightening: a `write` token no longer manages access.
        let (status, c) = rig
            .call(Some(&format!("Bearer {write_token}")), add_member())
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::NewStricter),
            "{c:?}"
        );

        // A repository-restricted token never reaches a project.
        let (status, c) = rig
            .call(
                Some(&format!("Bearer {scoped_token}")),
                empty_request("GET", format!("/api/v1/projects/{mine}")),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(is_refusal(&c), "{c:?}");
        agrees(&c, LegacyOutcome::Refuse);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = ANY($1)")
            .bind(vec![write_id, scoped_id])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1 OR name = $2")
            .bind(group)
            .bind(&created)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
            .bind(manager)
            .execute(&pool)
            .await;
        delete_project(&pool, mine).await;
        delete_project(&pool, theirs).await;
        tdh::cleanup_user(&pool, member).await;
        tdh::cleanup_user(&pool, instance_admin).await;
        tdh::cleanup(&pool, repo, manager).await;
    }

    #[tokio::test]
    async fn the_admin_area_is_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (admin, _) = tdh::create_user(&pool).await;
        let (plain, _) = tdh::create_user(&pool).await;
        let (global, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        // A global `admin` role assignment: `admin` on every repository in
        // legacy, never an instance administrator.
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, id, NULL FROM roles WHERE name = 'admin'",
        )
        .bind(global)
        .execute(&pool)
        .await
        .unwrap();
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let admin_bearer = tdh::bearer_for(&rig.state, admin).await;
        let plain_bearer = tdh::bearer_for(&rig.state, plain).await;
        let global_bearer = tdh::bearer_for(&rig.state, global).await;
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (scoped_token, scoped_id) = auth
            .generate_api_token(admin, "shadow-admin-scoped", vec!["*".into()], None)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(scoped_id)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        let scoped = format!("Bearer {scoped_token}");
        let get = |path: &str| empty_request("GET", format!("/api/v1/admin{path}"));
        let compared = |c: &Comparison, legacy: LegacyOutcome, class: Class| {
            assert_eq!((c.legacy, c.class), (legacy, class), "{c:?}");
        };

        // The administrator: reads agree, and so do a missing object and an
        // invalid value after the middleware.
        let (status, c) = rig.call(Some(&admin_bearer), get("/settings/system")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::SystemSettingsRead);
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let (status, c) = rig.call(Some(&admin_bearer), get("/backups")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::SystemBackupManage);
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let missing = format!("/backups/{}", Uuid::new_v4());
        let (status, c) = rig.call(Some(&admin_bearer), get(&missing)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let invalid = json_request(
            "PATCH",
            "/api/v1/admin/settings/system".to_string(),
            serde_json::json!({}),
        );
        let (status, c) = rig.call(Some(&admin_bearer), invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(c.permission, Permission::SystemSettingsUpdate);
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        // A non-administrator is refused by both, and compared as itself.
        let (status, c) = rig.call(Some(&plain_bearer), get("/audit")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.principal.id(), Some(plain));
        assert!(is_refusal(&c), "{c:?}");
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // The enumerated tightening: a repository-restricted administrator
        // token no longer reaches the instance...
        let (status, c) = rig.call(Some(&scoped), get("/settings/system")).await;
        assert_eq!(status, StatusCode::OK);
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);
        // ...where legacy already refuses it, both agree.
        let (status, c) = rig.call(Some(&scoped), get("/stats")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // A global `admin` role is `owner` on the instance: the age-gate queue
        // is the one admin operation it reaches, which legacy refuses.
        let (status, c) = rig
            .call(Some(&global_bearer), get("/age-gate/reviews"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::AgeGateReview);
        compared(&c, LegacyOutcome::Refuse, Class::NewWider);
        let (status, c) = rig
            .call(Some(&global_bearer), get("/settings/system"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(scoped_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(global)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, plain).await;
        tdh::cleanup_user(&pool, global).await;
        tdh::cleanup(&pool, repo, admin).await;
    }

    #[tokio::test]
    async fn identity_administration_is_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (admin, _) = tdh::create_user(&pool).await;
        let (plain, _) = tdh::create_user(&pool).await;
        let (manager, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        // A project administrator holds `iam.manage` on that project only.
        let project = new_project(&pool).await;
        tdh::grant_permission(&pool, "user", manager, "project", project, &["admin"]).await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let admin_bearer = tdh::bearer_for(&rig.state, admin).await;
        let plain_bearer = tdh::bearer_for(&rig.state, plain).await;
        let manager_bearer = tdh::bearer_for(&rig.state, manager).await;
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (users_token, users_id) = auth
            .generate_api_token(
                admin,
                "shadow-write-users",
                vec!["write:users".into()],
                None,
            )
            .await
            .unwrap();
        let users_only = format!("Bearer {users_token}");
        let compared = |c: &Comparison, legacy: LegacyOutcome, class: Class| {
            assert_eq!((c.legacy, c.class), (legacy, class), "{c:?}");
        };

        // Service accounts: the administrator agrees, a missing account
        // included; a non-administrator is refused by both, as itself.
        let (status, c) = rig
            .call(
                Some(&admin_bearer),
                empty_request("GET", "/api/v1/service-accounts".into()),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::ServiceAccountManage);
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let missing = format!("/api/v1/service-accounts/{}", Uuid::new_v4());
        let (status, c) = rig
            .call(Some(&admin_bearer), empty_request("GET", missing))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                empty_request("GET", "/api/v1/service-accounts".into()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.principal.id(), Some(plain));
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // A named user: another user's tokens through the administrator
        // branch, and a refused non-administrator, on the instance.
        let (status, c) = rig
            .call(
                Some(&admin_bearer),
                empty_request("GET", format!("/api/v1/users/{plain}/tokens")),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::UserCredentialsManage);
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                empty_request("GET", format!("/api/v1/users/{admin}")),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);
        // The caller's own id is self-service: not compared.
        let own = json_request(
            "POST",
            format!("/api/v1/users/{plain}/password"),
            serde_json::json!({}),
        );
        let (_, c) = rig.call(Some(&plain_bearer), own).await;
        assert_eq!(c.class, Class::Inconclusive("self_service"));

        // An administrator's `write:users` token administers no user.
        let create = json_request(
            "POST",
            "/api/v1/users".into(),
            serde_json::json!({"username": format!("shadow-{}", Uuid::new_v4()), "email": "s@example.com"}),
        );
        let (status, c) = rig.call(Some(&users_only), create).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::UserManage);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // The access API: a project administrator is refused by both; an
        // administrator's invalid grant is rejected after the check.
        let (status, c) = rig
            .call(
                Some(&manager_bearer),
                empty_request("GET", "/api/v1/permissions".into()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::IamManage);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);
        let invalid = json_request("POST", "/api/v1/permissions".into(), serde_json::json!({}));
        let (status, c) = rig.call(Some(&admin_bearer), invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(users_id)
            .execute(&pool)
            .await;
        delete_project(&pool, project).await;
        tdh::cleanup_user(&pool, plain).await;
        tdh::cleanup_user(&pool, manager).await;
        tdh::cleanup(&pool, repo, admin).await;
    }

    #[tokio::test]
    async fn instance_security_operations_are_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (admin, _) = tdh::create_user(&pool).await;
        let (plain, _) = tdh::create_user(&pool).await;
        let (reader, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        // A global `reader` role assignment reads every repository's findings.
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, id, NULL FROM roles WHERE name = 'reader'",
        )
        .bind(reader)
        .execute(&pool)
        .await
        .unwrap();
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let admin_bearer = tdh::bearer_for(&rig.state, admin).await;
        let plain_bearer = tdh::bearer_for(&rig.state, plain).await;
        let reader_bearer = tdh::bearer_for(&rig.state, reader).await;
        let get = |path: &str| empty_request("GET", format!("/api/v1{path}"));
        let compared = |c: &Comparison, legacy: LegacyOutcome, class: Class| {
            assert_eq!((c.legacy, c.class), (legacy, class), "{c:?}");
        };

        // The dashboard: the administrator agrees, a plain user is refused by
        // both, and a global reader is wider.
        let (status, c) = rig
            .call(Some(&admin_bearer), get("/security/dashboard"))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::SecurityRead);
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::Agree);
        let (status, c) = rig
            .call(Some(&plain_bearer), get("/security/dashboard"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.principal.id(), Some(plain));
        compared(&c, LegacyOutcome::Refuse, Class::Agree);
        let (status, c) = rig
            .call(Some(&reader_bearer), get("/security/dashboard"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        compared(&c, LegacyOutcome::Refuse, Class::NewWider);

        // Dependency-Track is behind the administrator middleware.
        let (status, c) = rig
            .call(Some(&plain_bearer), get("/dependency-track/projects"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::SecurityRead);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // The enumerated tightening: every repository's scan configuration
        // needs `security.read` on the instance.
        let (status, c) = rig
            .call(Some(&plain_bearer), get("/security/configs"))
            .await;
        assert_eq!(status, StatusCode::OK);
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);
        let (status, c) = rig
            .call(Some(&reader_bearer), get("/security/configs"))
            .await;
        assert_eq!(status, StatusCode::OK);
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        // A missing policy after the administrator check is a legacy permit.
        let missing = format!("/api/v1/security/policies/{}", Uuid::new_v4());
        let (status, c) = rig
            .call(Some(&admin_bearer), empty_request("DELETE", missing))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.permission, Permission::SecurityPolicyManage);
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(reader)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, plain).await;
        tdh::cleanup_user(&pool, reader).await;
        tdh::cleanup(&pool, repo, admin).await;
    }

    /// An artifact row in `repo`, with no stored content.
    async fn insert_artifact(pool: &PgPool, repo: Uuid) -> Uuid {
        let path = format!("objects/{}.bin", Uuid::new_v4());
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) \
             VALUES ($1, $2, 'object.bin', 1, repeat('0', 64), 'application/octet-stream', $2) \
             RETURNING id",
        )
        .bind(repo)
        .bind(path)
        .fetch_one(pool)
        .await
        .expect("insert an artifact")
    }

    /// One object of each security kind in `repo`, by resolver kind.
    async fn insert_security_objects(
        pool: &PgPool,
        repo: Uuid,
        artifact: Uuid,
    ) -> Vec<(&'static str, Uuid)> {
        let one = |sql: &'static str| async move {
            sqlx::query_scalar::<_, Uuid>(sql)
                .bind(repo)
                .bind(artifact)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("{sql}: {e}"))
        };
        let scan = one(
            "INSERT INTO scan_results (repository_id, artifact_id, scan_type) \
             VALUES ($1, $2, 'dependency') RETURNING id",
        )
        .await;
        let finding: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title) \
             VALUES ($1, $2, 'high', 'shadow') RETURNING id",
        )
        .bind(scan)
        .bind(artifact)
        .fetch_one(pool)
        .await
        .unwrap();
        let sbom = one(
            "INSERT INTO sbom_documents (repository_id, artifact_id, format, format_version, \
             content, content_hash) VALUES ($1, $2, 'cyclonedx', '1.5', '{}', 'h') RETURNING id",
        )
        .await;
        let cve = one("INSERT INTO cve_history (artifact_id, cve_id) \
             SELECT $2::uuid, 'CVE-2024-0001' WHERE $1::uuid IS NOT NULL RETURNING id")
        .await;
        let check = one(
            "INSERT INTO quality_check_results (repository_id, artifact_id, check_type) \
             VALUES ($1, $2, 'metadata') RETURNING id",
        )
        .await;
        let issue: Uuid = sqlx::query_scalar(
            "INSERT INTO quality_check_issues (check_result_id, artifact_id, severity, category, title) \
             VALUES ($1, $2, 'low', 'metadata', 'shadow') RETURNING id",
        )
        .bind(check)
        .bind(artifact)
        .fetch_one(pool)
        .await
        .unwrap();
        let ack = one(ACKNOWLEDGEMENT).await;
        vec![
            ("artifact:artifact_id", artifact),
            ("scan:id", scan),
            ("finding:id", finding),
            ("sbom:id", sbom),
            ("cve_entry:id", cve),
            ("cve_subject:id", artifact),
            ("quality_check:id", check),
            ("quality_issue:id", issue),
            ("acknowledgement:id", ack),
        ]
    }

    const ACKNOWLEDGEMENT: &str =
        "INSERT INTO finding_acknowledgements (repository_id, lineage_id, checksum_sha256, \
         finding_class, advisory_key, component_key, component_version_key, max_severity_rank, \
         created_via) \
         SELECT $1::uuid, gen_random_uuid(), repeat('0', 64), 'vulnerability', \
                'CVE-' || $2::text, 'c', 'v', 1, 'api' RETURNING id";

    #[tokio::test]
    async fn security_objects_resolve_to_their_repository() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact = insert_artifact(&pool, repo).await;
        let objects = insert_security_objects(&pool, repo, artifact).await;
        let global: Uuid = sqlx::query_scalar(ACKNOWLEDGEMENT)
            .bind(None::<Uuid>)
            .bind(Uuid::new_v4())
            .fetch_one(&pool)
            .await
            .unwrap();
        let resolve_as = |id: &str, param: String| {
            let pool = pool.clone();
            let resolver = Resolver::lookup(id).unwrap_or_else(|| panic!("{id} registered"));
            async move { resolve(&pool, resolver, Some(&param)).await }
        };
        let here = Ok(ScopeRef::Repository(repo));
        for (id, object) in &objects {
            assert_eq!(resolve_as(id, object.to_string()).await, here, "{id}");
            assert_eq!(
                resolve_as(id, Uuid::new_v4().to_string()).await,
                Err("resource_not_found"),
                "{id} missing"
            );
            assert_eq!(
                resolve_as(id, "not-a-uuid".into()).await,
                Err("malformed_parameter"),
                "{id} malformed"
            );
        }
        assert_eq!(
            resolve_as("repository:repo_id", repo.to_string()).await,
            here
        );
        assert_eq!(
            resolve_as("repository:repo_id", Uuid::new_v4().to_string()).await,
            Err("resource_not_found")
        );
        assert_eq!(resolve_as("repo:repo_key", key.clone()).await, here);
        assert_eq!(resolve_as("repo:key", key).await, here);
        assert_eq!(
            resolve_as("acknowledgement:id", global.to_string()).await,
            Ok(ScopeRef::Instance)
        );
        assert_eq!(
            resolve_as("cve_subject:id", "CVE-2024-0001".into()).await,
            Ok(ScopeRef::Instance)
        );
        assert_eq!(
            resolve_as("cve_subject:id", "ghsa-abcd-efgh-ijkl".into()).await,
            Ok(ScopeRef::Instance)
        );

        let _ =
            sqlx::query("DELETE FROM finding_acknowledgements WHERE id = $1 OR repository_id = $2")
                .bind(global)
                .bind(repo)
                .execute(&pool)
                .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn security_object_operations_are_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (other, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact = insert_artifact(&pool, repo).await;
        let elsewhere = insert_artifact(&pool, other).await;
        let (admin, _) = tdh::create_user(&pool).await;
        let (plain, _) = tdh::create_user(&pool).await;
        let (owner, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        tdh::grant_repo_role(&pool, repo, owner, "repository-owner").await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let admin_bearer = tdh::bearer_for(&rig.state, admin).await;
        let plain_bearer = tdh::bearer_for(&rig.state, plain).await;
        let owner_bearer = tdh::bearer_for(&rig.state, owner).await;
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (scoped_token, scoped_id) = auth
            .generate_api_token(admin, "shadow-security-scoped", vec!["*".into()], None)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(scoped_id)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        let scoped = format!("Bearer {scoped_token}");
        let get = |path: String| empty_request("GET", format!("/api/v1{path}"));
        let post = |path: String| empty_request("POST", format!("/api/v1{path}"));
        let compared = |c: &Comparison, legacy: LegacyOutcome, class: Class| {
            assert_eq!((c.legacy, c.class), (legacy, class), "{c:?}");
        };
        let here = Some(ScopeRef::Repository(repo));

        // A private repository's artifact health: both refuse, on its
        // repository. The handler looks the score up before the visibility
        // check, so the artifact needs one.
        sqlx::query("INSERT INTO artifact_health_scores (artifact_id) VALUES ($1)")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                get(format!("/quality/health/artifacts/{artifact}")),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.permission, Permission::SecurityRead);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // CVE history of the same artifact: the SBOM helper marks its refusal.
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                get(format!("/sbom/cve/history/{artifact}")),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // CVE history by CVE id is decided on the instance.
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                get("/sbom/cve/history/CVE-2024-0001".into()),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);

        // Signing keys need signing key management.
        let (status, c) = rig
            .call(Some(&plain_bearer), get("/signing/keys".into()))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::SigningKeyManage);
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);

        // A repository owner triggering a scan: refused today, permitted by
        // the model on the repository the body names.
        let scan = json_request(
            "POST",
            "/api/v1/security/scan".into(),
            serde_json::json!({ "artifact_id": artifact }),
        );
        let (status, c) = rig.call(Some(&owner_bearer), scan).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::SecurityScan);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::NewWider);

        // A scan of a missing artifact reports no target.
        let missing = json_request(
            "POST",
            "/api/v1/security/scan".into(),
            serde_json::json!({ "artifact_id": Uuid::new_v4() }),
        );
        let (_, c) = rig.call(Some(&owner_bearer), missing).await;
        assert_eq!(c.class, Class::Inconclusive("target_not_reported"));

        // Releasing an artifact that is not quarantined: a client error after
        // the administrator check is a permit.
        let (status, c) = rig
            .call(
                Some(&admin_bearer),
                post(format!("/quarantine/{artifact}/release")),
            )
            .await;
        assert!(status.is_client_error(), "{status}");
        assert_eq!(c.permission, Permission::SecurityQuarantine);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        // The same administrator's token restricted to the first repository
        // stays out of the other one.
        let (status, c) = rig
            .call(
                Some(&scoped),
                post(format!("/quarantine/{elsewhere}/release")),
            )
            .await;
        assert!(status.is_client_error(), "{status}");
        assert_eq!(c.resource, Some(ScopeRef::Repository(other)));
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(scoped_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(other)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, plain).await;
        tdh::cleanup(&pool, repo, owner).await;
        tdh::cleanup_user(&pool, admin).await;
    }

    /// A webhook of `repo`, or an instance-wide one for `None`.
    async fn insert_webhook(pool: &PgPool, repo: Option<Uuid>) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO webhooks (name, url, events, is_enabled, repository_id) \
             VALUES ('shadow', 'http://198.51.100.7/hook', ARRAY['artifact_uploaded'], true, $1) \
             RETURNING id",
        )
        .bind(repo)
        .fetch_one(pool)
        .await
        .expect("insert a webhook")
    }

    #[tokio::test]
    async fn a_webhook_resolves_to_its_repository_or_the_instance() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        let hook = insert_webhook(&pool, Some(repo)).await;
        let global = insert_webhook(&pool, None).await;
        let resolver = Resolver::lookup("webhook:id").unwrap();
        let resolve_as = |param: String| {
            let pool = pool.clone();
            async move { resolve(&pool, resolver, Some(&param)).await }
        };
        let here = resolve_as(hook.to_string()).await;
        let instance = resolve_as(global.to_string()).await;
        let missing = resolve_as(Uuid::new_v4().to_string()).await;
        let malformed = resolve_as("hook".into()).await;
        let _ = sqlx::query("DELETE FROM webhooks WHERE id = ANY($1)")
            .bind(vec![hook, global])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
        assert_eq!(here, Ok(ScopeRef::Repository(repo)));
        assert_eq!(instance, Ok(ScopeRef::Instance));
        assert_eq!(missing, Err("resource_not_found"));
        assert_eq!(malformed, Err("malformed_parameter"));
    }

    #[tokio::test]
    async fn integration_operations_are_compared() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (admin, _) = tdh::create_user(&pool).await;
        let (plain, _) = tdh::create_user(&pool).await;
        let (reader, _) = tdh::create_user(&pool).await;
        let (owner, _) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        tdh::grant_repo_role(&pool, repo, reader, "reader").await;
        tdh::grant_repo_role(&pool, repo, owner, "repository-owner").await;
        let hook = insert_webhook(&pool, Some(repo)).await;
        let global = insert_webhook(&pool, None).await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let admin_bearer = tdh::bearer_for(&rig.state, admin).await;
        let plain_bearer = tdh::bearer_for(&rig.state, plain).await;
        let reader_bearer = tdh::bearer_for(&rig.state, reader).await;
        let owner_bearer = tdh::bearer_for(&rig.state, owner).await;
        let get = |path: String| empty_request("GET", format!("/api/v1{path}"));
        let post = |path: String| empty_request("POST", format!("/api/v1{path}"));
        let compared = |c: &Comparison, legacy: LegacyOutcome, class: Class| {
            assert_eq!((c.legacy, c.class), (legacy, class), "{c:?}");
        };
        let here = Some(ScopeRef::Repository(repo));

        // Migrations are the instance administrator's.
        let (status, c) = rig
            .call(Some(&admin_bearer), get("/migrations".into()))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::MigrationManage);
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        // Plugin management: a plain user is refused by both.
        let (status, c) = rig
            .call(
                Some(&plain_bearer),
                post(format!("/plugins/{}/enable", Uuid::new_v4())),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.permission, Permission::PluginManage);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // A repository reader reads its webhook today; the model refuses.
        let (status, c) = rig
            .call(Some(&reader_bearer), get(format!("/webhooks/{hook}")))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::RepositoryNotificationsManage);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Permit, Class::NewStricter);

        // A stranger to the private repository is refused by both.
        let (status, c) = rig
            .call(Some(&plain_bearer), get(format!("/webhooks/{hook}")))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // The repository owner manages its webhooks under the model.
        let (status, c) = rig
            .call(
                Some(&owner_bearer),
                post(format!("/webhooks/{hook}/disable")),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::NewWider);

        // Creating a webhook is decided on the repository the body names.
        let create = json_request(
            "POST",
            "/api/v1/webhooks".into(),
            serde_json::json!({
                "name": "shadow",
                "url": "http://198.51.100.7/hook",
                "events": ["artifact_uploaded"],
                "repository_id": repo,
            }),
        );
        let (status, c) = rig.call(Some(&plain_bearer), create).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(c.resource, here);
        compared(&c, LegacyOutcome::Refuse, Class::Agree);

        // An instance-wide webhook is decided on the instance.
        let (status, c) = rig
            .call(
                Some(&admin_bearer),
                post(format!("/webhooks/{global}/disable")),
            )
            .await;
        assert!(status.is_success(), "{status}");
        assert_eq!(c.resource, Some(ScopeRef::Instance));
        compared(&c, LegacyOutcome::Permit, Class::Agree);

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM webhooks WHERE id = ANY($1)")
            .bind(vec![hook, global])
            .execute(&pool)
            .await;
        for user in [plain, reader, owner] {
            tdh::cleanup_user(&pool, user).await;
        }
        tdh::cleanup(&pool, repo, admin).await;
    }

    #[tokio::test]
    async fn storage_gc_by_a_non_administrator_agrees() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (owner, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, repo, owner).await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let bearer = tdh::bearer_for(&rig.state, owner).await;

        let gc = json_request(
            "POST",
            format!("/api/v1/repositories/{key}/storage-gc"),
            serde_json::json!({"dry_run": true}),
        );
        let (status, c) = rig.call(Some(&bearer), gc).await;
        assert!(status.is_client_error(), "{status}");
        assert_eq!(c.permission, Permission::SystemMaintenance);
        assert!(is_refusal(&c), "{c:?}");
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Refuse, Class::Agree),
            "{c:?}"
        );

        rig.shutdown.cancel();
        tdh::cleanup(&pool, repo, owner).await;
    }

    #[tokio::test]
    async fn refusals_outside_the_declared_decision_are_inconclusive() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (virt, virt_key, dir) = tdh::create_repo(&pool, "virtual", "generic").await;
        let (hidden, hidden_key, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (owner, _) = tdh::create_user(&pool).await;
        let (reader, _) = tdh::create_user(&pool).await;
        let (peer, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, virt, owner).await;
        tdh::grant_repo_role(&pool, virt, reader, "reader").await;
        tdh::grant_repo_role(&pool, virt, peer, "developer").await;
        let mut rig = Rig::new(pool.clone(), &dir).await;
        let owner_bearer = tdh::bearer_for(&rig.state, owner).await;
        let reader_bearer = tdh::bearer_for(&rig.state, reader).await;

        // The member repository is hidden from the caller: the 404 is about
        // it, not about the virtual repository the declaration names.
        let add = json_request(
            "POST",
            format!("/api/v1/repositories/{virt_key}/members"),
            serde_json::json!({"member_key": hidden_key}),
        );
        let (status, c) = rig.call(Some(&owner_bearer), add).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.resource, Some(ScopeRef::Repository(virt)));
        assert_eq!(c.class, Class::Inconclusive("secondary_resource"), "{c:?}");

        // A reader asks for the conda allowlist of a generic repository: the
        // type check answers before the administrator check.
        let allowlist = empty_request("GET", format!("/api/v1/repositories/{virt_key}/allowlist"));
        let (status, c) = rig.call(Some(&reader_bearer), allowlist).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            c.class,
            Class::Inconclusive("validation_before_authorization"),
            "{c:?}"
        );

        // The owner reads a token another user created: the handler hides it.
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(rig.state.config.clone()),
        );
        let (_, token_id) = auth
            .generate_api_token(peer, "peer-token", vec!["read:artifacts".into()], None)
            .await
            .unwrap();
        sqlx::query("UPDATE api_tokens SET created_by_user_id = $1 WHERE id = $2")
            .bind(peer)
            .bind(token_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(token_id)
            .bind(virt)
            .execute(&pool)
            .await
            .unwrap();
        let read = empty_request(
            "GET",
            format!("/api/v1/repositories/{virt_key}/tokens/{token_id}"),
        );
        let (status, c) = rig.call(Some(&owner_bearer), read).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(c.legacy, LegacyOutcome::KeptRefusal, "{c:?}");
        assert!(
            c.decision.as_ref().is_some_and(Decision::is_permit),
            "{c:?}"
        );
        assert_eq!(c.class, Class::Inconclusive("handler_check"), "{c:?}");

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&pool)
            .await;
        delete_repository(&pool, hidden).await;
        tdh::cleanup_user(&pool, reader).await;
        tdh::cleanup_user(&pool, peer).await;
        tdh::cleanup(&pool, virt, owner).await;
    }

    #[tokio::test]
    async fn a_repository_administrator_decides_an_age_gate_review() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let (owner, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, repo, owner).await;
        let review: Uuid = sqlx::query_scalar(
            "INSERT INTO age_gate_reviews \
             (repository_id, package_name, package_version, status) \
             VALUES ($1, 'shadow-pkg', '1.0.0', 'pending') RETURNING id",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        let storage = dir.to_string_lossy().to_string();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &storage);
        let base = tdh::build_state_with_proxy_and_age_gate(pool.clone(), &storage, proxy);
        let mut rig = Rig::over(pool.clone(), base).await;
        let bearer = tdh::bearer_for(&rig.state, owner).await;

        let approve = json_request(
            "POST",
            format!("/api/v1/repositories/{key}/age-gate/reviews/{review}/approve"),
            serde_json::json!({}),
        );
        let (status, c) = rig.call(Some(&bearer), approve).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(c.permission, Permission::AgeGateReview);
        assert_eq!(
            (c.legacy, c.class),
            (LegacyOutcome::Permit, Class::Agree),
            "{c:?}"
        );

        rig.shutdown.cancel();
        let _ = sqlx::query("DELETE FROM age_gate_reviews WHERE id = $1")
            .bind(review)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo, owner).await;
    }

    /// Send `request` through the real router without the layer, inside a
    /// recorder scope, and return the status and the kept-refusal reason.
    async fn kept_reason(
        state: &SharedState,
        credential: &str,
        request: HttpRequest<Body>,
    ) -> (StatusCode, Option<&'static str>) {
        recorded_reason(state, Some(credential), request).await
    }

    /// [`kept_reason`], also for an anonymous caller.
    async fn recorded_reason(
        state: &SharedState,
        credential: Option<&str>,
        mut request: HttpRequest<Body>,
    ) -> (StatusCode, Option<&'static str>) {
        if let Some(credential) = credential {
            request
                .headers_mut()
                .insert("authorization", credential.parse().unwrap());
        }
        let app = crate::api::routes::create_router(state.clone());
        let ((status, _), recorded) =
            crate::api::authz::shadow_marker::scope(tdh::send(app, request)).await;
        (status, recorded.kept_refusal)
    }

    async fn new_project(pool: &PgPool) -> Uuid {
        sqlx::query_scalar("INSERT INTO projects (key, name) VALUES ($1, $1) RETURNING id")
            .bind(format!("prj-kept-{}", Uuid::new_v4().simple()))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn delete_project(pool: &PgPool, project: Uuid) {
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(project)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn handler_refusals_carry_their_reason() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        let (virt, virt_key, _) = tdh::create_repo(&pool, "virtual", "generic").await;
        let (internal, internal_key, _) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query("UPDATE repositories SET visibility = 'internal' WHERE id = $1")
            .bind(internal)
            .execute(&pool)
            .await
            .unwrap();
        let (owner, _) = tdh::create_user(&pool).await;
        let (developer, _) = tdh::create_user(&pool).await;
        let (reader, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, repo, owner).await;
        tdh::grant_repo_admin(&pool, virt, owner).await;
        tdh::grant_repo_role(&pool, repo, developer, "developer").await;
        tdh::grant_repo_role(&pool, repo, reader, "reader").await;
        let state = tdh::build_state(pool.clone(), dir.to_str().unwrap());
        let owner_bearer = tdh::bearer_for(&state, owner).await;
        let developer_bearer = tdh::bearer_for(&state, developer).await;
        let reader_bearer = tdh::bearer_for(&state, reader).await;
        let put = |uri: String| HttpRequest::put(uri).body(Body::from("payload")).unwrap();

        // Seed an artifact, then make the repository promotion-only.
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            put(format!("/api/v1/repositories/{key}/artifacts/kept.txt")),
        )
        .await;
        assert!(status.is_success(), "{status}");
        assert_eq!(reason, None);
        sqlx::query("UPDATE repositories SET promotion_only = true WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        state.repo_cache.write().await.clear();
        let (status, reason) = kept_reason(
            &state,
            &developer_bearer,
            put(format!("/api/v1/repositories/{key}/artifacts/other.txt")),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("promotion_only"))
        );
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            empty_request(
                "DELETE",
                format!("/api/v1/repositories/{key}/artifacts/kept.txt"),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("promotion_only"))
        );

        // Repository tokens: an administrator-only scope, a scope the caller
        // cannot delegate, and another member's token.
        let mint = |scopes: serde_json::Value| {
            json_request(
                "POST",
                format!("/api/v1/repositories/{key}/tokens"),
                serde_json::json!({"name": "kept", "scopes": scopes}),
            )
        };
        let (status, reason) =
            kept_reason(&state, &developer_bearer, mint(serde_json::json!(["*"]))).await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("token_scope"))
        );
        let (status, reason) = kept_reason(
            &state,
            &reader_bearer,
            mint(serde_json::json!(["write:artifacts"])),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("token_scope"))
        );
        let auth = crate::services::auth_service::AuthService::new(
            pool.clone(),
            Arc::new(state.config.clone()),
        );
        let (_, token_id) = auth
            .generate_api_token(owner, "owner-token", vec!["read:artifacts".into()], None)
            .await
            .unwrap();
        sqlx::query("UPDATE api_tokens SET created_by_user_id = $1 WHERE id = $2")
            .bind(owner)
            .bind(token_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(token_id)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        let (status, reason) = kept_reason(
            &state,
            &developer_bearer,
            empty_request(
                "DELETE",
                format!("/api/v1/repositories/{key}/tokens/{token_id}"),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::NOT_FOUND, Some("token_owner"))
        );

        // Replication routes accept peer requests only.
        let digest = format!("sha256:{}", "0".repeat(64));
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            put(format!("/api/v1/repositories/{key}/oci/blobs/{digest}")),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("replication_only"))
        );

        // An internal member needs a read grant to be attached.
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            json_request(
                "POST",
                format!("/api/v1/repositories/{virt_key}/members"),
                serde_json::json!({"member_key": internal_key}),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("virtual_member"))
        );

        // A project administrator: a project they do not administer, and a
        // non-default storage backend.
        let mine = new_project(&pool).await;
        let theirs = new_project(&pool).await;
        tdh::grant_permission(&pool, "user", owner, "project", mine, &["admin"]).await;
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            json_request(
                "PATCH",
                format!("/api/v1/repositories/{key}"),
                serde_json::json!({"project_id": theirs}),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("target_project"))
        );
        let created = format!("kept-create-{}", Uuid::new_v4().simple());
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            json_request(
                "POST",
                "/api/v1/repositories".to_string(),
                serde_json::json!({
                    "key": created, "name": created, "format": "generic",
                    "repo_type": "local", "project_id": mine,
                    "storage_backend": "kept-not-the-default",
                }),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("admin_only_option"))
        );

        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(token_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
        delete_project(&pool, mine).await;
        delete_project(&pool, theirs).await;
        delete_repository(&pool, internal).await;
        delete_repository(&pool, virt).await;
        tdh::cleanup_user(&pool, developer).await;
        tdh::cleanup_user(&pool, reader).await;
        tdh::cleanup(&pool, repo, owner).await;
    }

    #[tokio::test]
    async fn mcp_refusals_carry_their_reason() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = tdh::create_repo(&pool, "local", "mcp").await;
        let (owner, _) = tdh::create_user(&pool).await;
        let (stranger, _) = tdh::create_user(&pool).await;
        tdh::grant_repo_admin(&pool, repo, owner).await;
        let state = tdh::build_state(pool.clone(), dir.to_str().unwrap());
        let owner_bearer = tdh::bearer_for(&state, owner).await;
        let stranger_bearer = tdh::bearer_for(&state, stranger).await;

        // Health has no anonymous or grant-free baseline.
        for credential in [None, Some(stranger_bearer.as_str())] {
            let (status, reason) = recorded_reason(
                &state,
                credential,
                empty_request(
                    "GET",
                    format!("/api/v1/repositories/{key}/mcp/servers/kept/versions/1.0.0/health"),
                ),
            )
            .await;
            assert_eq!(
                (status, reason),
                (StatusCode::NOT_FOUND, Some("grant_required")),
                "anonymous: {}",
                credential.is_none()
            );
        }

        // Only an instance administrator sets an MCP lock, on update and on
        // create alike.
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            json_request(
                "PATCH",
                format!("/api/v1/repositories/{key}"),
                serde_json::json!({"mcp_probe_remotes_locked": true}),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("admin_only_option"))
        );
        let project = new_project(&pool).await;
        tdh::grant_permission(&pool, "user", owner, "project", project, &["admin"]).await;
        let created = format!("kept-mcp-{}", Uuid::new_v4().simple());
        let (status, reason) = kept_reason(
            &state,
            &owner_bearer,
            json_request(
                "POST",
                "/api/v1/repositories".to_string(),
                serde_json::json!({
                    "key": created, "name": created, "format": "mcp",
                    "repo_type": "local", "project_id": project,
                    "mcp_probe_remotes_locked": true,
                }),
            ),
        )
        .await;
        assert_eq!(
            (status, reason),
            (StatusCode::FORBIDDEN, Some("admin_only_option"))
        );

        delete_project(&pool, project).await;
        tdh::cleanup_user(&pool, stranger).await;
        tdh::cleanup(&pool, repo, owner).await;
    }
}
