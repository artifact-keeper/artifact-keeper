//! System-wide maintenance / downtime banners (#2155).
//!
//! * `GET /api/v1/banners` -- public (no auth, exempt from the guest-access
//!   guard so the login page can show it): the banners active right now,
//!   optionally filtered to `?target=ui|api`.
//! * `/api/v1/admin/banners[/{id}]` -- admin CRUD, gated by the admin block's
//!   `admin_middleware`. Every mutation is audited.

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::banner_service::{self, Banner, BannerInput, BannerSeverity, BannerTarget};

/// Public routes, nested at `/api/v1/banners`.
pub fn public_router() -> Router<SharedState> {
    Router::new().route("/", get(list_active_banners))
}

/// Admin routes, nested at `/api/v1/admin/banners` inside the admin block.
pub fn admin_router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_banners).post(create_banner))
        .route(
            "/:id",
            get(get_banner).put(update_banner).delete(delete_banner),
        )
}

/// A banner as shown to readers: no authorship or enable flag.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct PublicBanner {
    pub id: Uuid,
    pub title: String,
    pub message: String,
    pub severity: BannerSeverity,
    pub target: BannerTarget,
    pub link_url: Option<String>,
    pub starts_at: Option<chrono::DateTime<Utc>>,
    pub ends_at: Option<chrono::DateTime<Utc>>,
}

impl From<Banner> for PublicBanner {
    fn from(b: Banner) -> Self {
        PublicBanner {
            id: b.id,
            title: b.title,
            message: b.message,
            severity: b.severity,
            target: b.target,
            link_url: b.link_url,
            starts_at: b.starts_at,
            ends_at: b.ends_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActiveBannersResponse {
    /// Active banners, most severe first.
    pub banners: Vec<PublicBanner>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ActiveBannersQuery {
    /// `ui` or `api` to get the banners for that surface (plus the ones for
    /// every surface); omit for all active banners.
    pub target: Option<BannerTarget>,
}

/// An admin's view of a banner: everything stored, plus whether it is
/// displayed right now.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminBanner {
    #[serde(flatten)]
    pub banner: Banner,
    /// Enabled and inside its display window at the time of the request.
    pub active: bool,
}

impl AdminBanner {
    fn at(banner: Banner, now: chrono::DateTime<Utc>) -> Self {
        let active = banner.is_active_at(now);
        AdminBanner { banner, active }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BannerListResponse {
    pub banners: Vec<AdminBanner>,
}

/// List the banners active right now.
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/banners",
    tag = "banners",
    params(ActiveBannersQuery),
    responses(
        (status = 200, description = "Active banners", body = ActiveBannersResponse),
    )
)]
pub async fn list_active_banners(
    State(state): State<SharedState>,
    Query(query): Query<ActiveBannersQuery>,
) -> Result<Json<ActiveBannersResponse>> {
    let banners = banner_service::list_active(&state.db, Utc::now(), query.target).await?;
    Ok(Json(ActiveBannersResponse {
        banners: banners.into_iter().map(PublicBanner::from).collect(),
    }))
}

/// List every banner, including disabled, scheduled and expired ones.
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/admin/banners",
    tag = "banners",
    responses(
        (status = 200, description = "All banners", body = BannerListResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_banners(State(state): State<SharedState>) -> Result<Json<BannerListResponse>> {
    let now = Utc::now();
    let banners = banner_service::list_all(&state.db).await?;
    Ok(Json(BannerListResponse {
        banners: banners
            .into_iter()
            .map(|b| AdminBanner::at(b, now))
            .collect(),
    }))
}

/// Read one banner.
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/admin/banners",
    tag = "banners",
    params(("id" = Uuid, Path, description = "Banner ID")),
    responses(
        (status = 200, description = "The banner", body = AdminBanner),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "No such banner", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_banner(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminBanner>> {
    let banner = banner_service::get(&state.db, id)
        .await?
        .ok_or_else(|| not_found(id))?;
    Ok(Json(AdminBanner::at(banner, Utc::now())))
}

/// Create a banner.
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/admin/banners",
    tag = "banners",
    request_body = BannerInput,
    responses(
        (status = 201, description = "Banner created", body = AdminBanner),
        (status = 400, description = "Invalid banner", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_banner(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(input): Json<BannerInput>,
) -> Result<(StatusCode, Json<AdminBanner>)> {
    let valid = banner_service::validate_input(input).map_err(AppError::Validation)?;
    let banner = banner_service::create(&state.db, &valid, auth.user_id).await?;
    audit_banner(&state, &auth, "created", None, Some(&banner)).await;
    Ok((
        StatusCode::CREATED,
        Json(AdminBanner::at(banner, Utc::now())),
    ))
}

/// Replace a banner's content, window and enabled flag.
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/admin/banners",
    tag = "banners",
    params(("id" = Uuid, Path, description = "Banner ID")),
    request_body = BannerInput,
    responses(
        (status = 200, description = "Banner updated", body = AdminBanner),
        (status = 400, description = "Invalid banner", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "No such banner", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_banner(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(input): Json<BannerInput>,
) -> Result<Json<AdminBanner>> {
    let valid = banner_service::validate_input(input).map_err(AppError::Validation)?;
    // The before-state, for the audit trail's from/to.
    let before = banner_service::get(&state.db, id)
        .await?
        .ok_or_else(|| not_found(id))?;
    let banner = banner_service::update(&state.db, id, &valid, auth.user_id)
        .await?
        .ok_or_else(|| not_found(id))?;
    audit_banner(&state, &auth, "updated", Some(&before), Some(&banner)).await;
    Ok(Json(AdminBanner::at(banner, Utc::now())))
}

/// Delete a banner.
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/admin/banners",
    tag = "banners",
    params(("id" = Uuid, Path, description = "Banner ID")),
    responses(
        (status = 204, description = "Banner deleted"),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "No such banner", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_banner(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let banner = banner_service::delete(&state.db, id)
        .await?
        .ok_or_else(|| not_found(id))?;
    audit_banner(&state, &auth, "deleted", Some(&banner), None).await;
    Ok(StatusCode::NO_CONTENT)
}

fn not_found(id: Uuid) -> AppError {
    AppError::NotFound(format!("banner {id} not found"))
}

/// Everything a reader sees, for the audit trail. `message` and `link_url`
/// are the fields that carry the abuse risk (a rewritten message or a
/// phishing link reaches every user, anonymous ones included), so they are
/// recorded in full; both are bounded by validation.
fn banner_audit_snapshot(b: &Banner) -> serde_json::Value {
    serde_json::json!({
        "title": b.title,
        "message": b.message,
        "link_url": b.link_url,
        "severity": b.severity.as_str(),
        "target": b.target.as_str(),
        "enabled": b.enabled,
        "starts_at": b.starts_at,
        "ends_at": b.ends_at,
    })
}

/// The audit `details` for a banner mutation: the state before (`from`, for
/// update and delete) and after (`to`, for create and update). Pure so its
/// shape is tested.
fn banner_audit_details(
    op: &str,
    id: Uuid,
    from: Option<&Banner>,
    to: Option<&Banner>,
) -> serde_json::Value {
    serde_json::json!({
        "setting": "system_banner",
        "op": op,
        "banner_id": id,
        "from": from.map(banner_audit_snapshot),
        "to": to.map(banner_audit_snapshot),
    })
}

async fn audit_banner(
    state: &SharedState,
    auth: &AuthExtension,
    op: &str,
    from: Option<&Banner>,
    to: Option<&Banner>,
) {
    let Some(subject) = to.or(from) else {
        return;
    };
    let entry = AuditEntry::new(AuditAction::SettingChanged, ResourceType::Setting)
        .user(auth.user_id)
        .actor_name(&auth.username)
        .resource(subject.id)
        .resource_name(format!("system_banner:{}", subject.title))
        .details(banner_audit_details(op, subject.id, from, to));
    audit_fire_and_forget(state.db.clone(), entry).await;
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_active_banners,
        list_banners,
        get_banner,
        create_banner,
        update_banner,
        delete_banner,
    ),
    components(schemas(
        Banner,
        BannerInput,
        BannerSeverity,
        BannerTarget,
        PublicBanner,
        ActiveBannersResponse,
        AdminBanner,
        BannerListResponse,
    ))
)]
pub struct BannersApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::Request;

    fn sample(enabled: bool) -> Banner {
        let now = Utc::now();
        Banner {
            id: Uuid::new_v4(),
            title: "Maintenance".into(),
            message: "Read-only tonight".into(),
            severity: BannerSeverity::Critical,
            target: BannerTarget::Ui,
            link_url: Some("https://status.example.com".into()),
            starts_at: None,
            ends_at: None,
            enabled,
            created_by: Some(Uuid::new_v4()),
            updated_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn public_view_drops_authorship_and_enabled() {
        let b = sample(true);
        let json = serde_json::to_value(PublicBanner::from(b.clone())).unwrap();
        assert_eq!(json["title"], "Maintenance");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["target"], "ui");
        assert!(json.get("created_by").is_none());
        assert!(json.get("enabled").is_none());
    }

    #[test]
    fn admin_view_flattens_and_computes_active() {
        let now = Utc::now();
        let on = serde_json::to_value(AdminBanner::at(sample(true), now)).unwrap();
        assert_eq!(on["active"], true);
        assert_eq!(on["enabled"], true);
        assert!(on.get("created_by").is_some());
        let off = serde_json::to_value(AdminBanner::at(sample(false), now)).unwrap();
        assert_eq!(off["active"], false);
    }

    #[test]
    fn audit_details_record_message_link_and_from_to() {
        let before = sample(true);
        let mut after = before.clone();
        after.message = "Re-enter your password at the link".into();
        after.link_url = Some("https://phish.example/".into());
        let d = banner_audit_details("updated", before.id, Some(&before), Some(&after));
        assert_eq!(d["op"], "updated");
        assert_eq!(d["setting"], "system_banner");
        assert_eq!(d["banner_id"], before.id.to_string());
        assert_eq!(d["from"]["message"], "Read-only tonight");
        assert_eq!(d["from"]["link_url"], "https://status.example.com");
        assert_eq!(d["to"]["message"], "Re-enter your password at the link");
        assert_eq!(d["to"]["link_url"], "https://phish.example/");
        assert_eq!(d["to"]["severity"], "critical");
        let created = banner_audit_details("created", after.id, None, Some(&after));
        assert!(created["from"].is_null());
        let deleted = banner_audit_details("deleted", before.id, Some(&before), None);
        assert!(deleted["to"].is_null());
        assert!(not_found(before.id)
            .to_string()
            .contains(&before.id.to_string()));
    }

    /// Handler-level: admin CRUD, the public endpoint's window/target
    /// filtering, and that the public route answers anonymous callers.
    #[tokio::test]
    async fn admin_crud_and_public_listing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp/banners-handler-test");
        let auth = tdh::admin_auth(user_id, &username);
        let tag = Uuid::new_v4().simple().to_string();
        let body = |suffix: &str, target: &str, extra: serde_json::Value| -> BannerInput {
            let mut v = serde_json::json!({
                "title": format!("{tag}-{suffix}"),
                "message": "Registry maintenance",
                "severity": "warning",
                "target": target,
            });
            for (k, val) in extra.as_object().unwrap() {
                v[k] = val.clone();
            }
            serde_json::from_value(v).unwrap()
        };

        // Invalid input is a 400 and creates nothing.
        let bad = create_banner(
            State(state.clone()),
            Extension(auth.clone()),
            Json(body(
                "bad",
                "all",
                serde_json::json!({"link_url": "javascript:alert(1)"}),
            )),
        )
        .await;
        assert!(matches!(bad, Err(AppError::Validation(_))));

        let (status, Json(api)) = create_banner(
            State(state.clone()),
            Extension(auth.clone()),
            Json(body("api", "api", serde_json::json!({}))),
        )
        .await
        .expect("create api banner");
        assert_eq!(status, StatusCode::CREATED);
        assert!(api.active);

        let past = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let less_past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let (_, Json(expired)) = create_banner(
            State(state.clone()),
            Extension(auth.clone()),
            Json(body(
                "expired",
                "all",
                serde_json::json!({"starts_at": past, "ends_at": less_past}),
            )),
        )
        .await
        .expect("create expired banner");
        assert!(!expired.active);

        let titles = |r: &ActiveBannersResponse| -> Vec<String> {
            r.banners
                .iter()
                .filter(|b| b.title.starts_with(&tag))
                .map(|b| b.title.clone())
                .collect()
        };

        // Public: only the active one; the ui filter hides the api-only banner.
        let Json(all) = list_active_banners(
            State(state.clone()),
            Query(ActiveBannersQuery { target: None }),
        )
        .await
        .unwrap();
        assert_eq!(titles(&all), [format!("{tag}-api")]);
        let Json(ui) = list_active_banners(
            State(state.clone()),
            Query(ActiveBannersQuery {
                target: Some(BannerTarget::Ui),
            }),
        )
        .await
        .unwrap();
        assert!(titles(&ui).is_empty());

        // Through the router, anonymously: the public route needs no auth.
        let app = tdh::router_anon(public_router(), state.clone());
        let (code, bytes) = tdh::send(
            app,
            Request::builder()
                .uri("/?target=api")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["banners"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["title"] == format!("{tag}-api")));

        // Admin list sees both, with the computed flag.
        let Json(listed) = list_banners(State(state.clone())).await.unwrap();
        let ours: Vec<_> = listed
            .banners
            .iter()
            .filter(|b| b.banner.title.starts_with(&tag))
            .collect();
        assert_eq!(ours.len(), 2);

        // Update: disable the api banner; it drops out of the public list.
        let Json(updated) = update_banner(
            State(state.clone()),
            Extension(auth.clone()),
            Path(api.banner.id),
            Json(body("api", "api", serde_json::json!({"enabled": false}))),
        )
        .await
        .expect("update");
        assert!(!updated.active);
        let Json(after) = list_active_banners(
            State(state.clone()),
            Query(ActiveBannersQuery { target: None }),
        )
        .await
        .unwrap();
        assert!(titles(&after).is_empty());

        let Json(one) = get_banner(State(state.clone()), Path(api.banner.id))
            .await
            .expect("get");
        assert!(!one.banner.enabled);

        // Missing ids are 404 on every by-id route.
        let missing = Uuid::new_v4();
        assert!(matches!(
            get_banner(State(state.clone()), Path(missing)).await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            update_banner(
                State(state.clone()),
                Extension(auth.clone()),
                Path(missing),
                Json(body("x", "all", serde_json::json!({}))),
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            delete_banner(State(state.clone()), Extension(auth.clone()), Path(missing)).await,
            Err(AppError::NotFound(_))
        ));

        for id in [api.banner.id, expired.banner.id] {
            assert_eq!(
                delete_banner(State(state.clone()), Extension(auth.clone()), Path(id))
                    .await
                    .unwrap(),
                StatusCode::NO_CONTENT
            );
        }
        // Mutations were audited.
        assert!(tdh::audit_count_eventually(&pool, api.banner.id, "SETTING_CHANGED", 3).await >= 3);
        // The update row records the before and after content.
        let from_to: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
            "SELECT details->'from'->>'message', (details->'to'->>'enabled')::boolean \
             FROM audit_log WHERE resource_id = $1 AND details->>'op' = 'updated'",
        )
        .bind(api.banner.id)
        .fetch_optional(&pool)
        .await
        .expect("query update audit row");
        assert_eq!(
            from_to,
            Some((Some("Registry maintenance".to_string()), Some(false)))
        );
        tdh::cleanup_user(&pool, user_id).await;
    }
}
