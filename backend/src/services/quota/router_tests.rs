//! The instance quotas through the production router (#5912), against a real
//! database (each test skips without `DATABASE_URL`).
//!
//! Instance usage is the sum over every repository's usage ledger, which the
//! other tests sharing the database change concurrently. So each test pins
//! the quota at `usage at start + 4 GiB` and moves usage with one "filler"
//! artifact row of a few GiB (its bytes are charged by the ledger triggers,
//! no object is written), and every decision it asserts is at least 1 GiB
//! away from the boundary, far beyond what any other test stores.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::handlers::test_db_helpers as tdh;

const GIB: i64 = 1 << 30;
/// `MAX_UPLOAD_SIZE` in these tests.
const MAX_UPLOAD: u64 = 1 << 20;

struct Fx {
    pool: PgPool,
    app: Router,
    auth: String,
    user_id: Uuid,
    repos: Vec<(Uuid, String, std::path::PathBuf)>,
    filler: Uuid,
    _serial: tdh::UsageLedgerSerialGuard,
}

impl Fx {
    async fn setup(formats: &[&str]) -> Option<Self> {
        let serial = tdh::usage_ledger_serial_lock().await;
        let pool = tdh::try_pool().await?;
        let mut repos = Vec::new();
        for format in formats {
            repos.push(tdh::create_repo(&pool, "local", format).await);
        }
        let base = super::storage::instance_used_bytes(&pool).await.unwrap();
        let quota = base + 4 * GIB as u64;
        let state = tdh::build_state_with(pool.clone(), repos[0].2.to_str().unwrap(), |c| {
            c.max_upload_size_bytes = MAX_UPLOAD;
            c.quotas.storage_quota_bytes = quota;
            c.quotas.help_url = Some("https://quota.example.test/usage".into());
        });
        let app = crate::api::routes::create_router(state.clone());

        let user_id = Uuid::new_v4();
        let username = format!("quota5912-{user_id}");
        let hash = bcrypt::hash("quotapass", 4).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, \
             is_active, password_changed_at, privileges_changed_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'local', true, true, NOW() - INTERVAL '60 seconds', \
             NOW() - INTERVAL '60 seconds', NOW() - INTERVAL '60 seconds', \
             NOW() - INTERVAL '60 seconds')",
        )
        .bind(user_id)
        .bind(&username)
        .bind(format!("{username}@test.local"))
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
        let auth = {
            use base64::Engine;
            let raw = format!("{username}:quotapass");
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            )
        };

        // The filler: a hosted row in the first repository, charged to the
        // ledger by its trigger; starts at 3 GiB (1 GiB of headroom left).
        let filler = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'filler/big.bin', 'big.bin', '1', $3, $4, \
                     'application/octet-stream', $5)",
        )
        .bind(filler)
        .bind(repos[0].0)
        .bind(3 * GIB)
        .bind(format!("{:064x}", 5912))
        .bind(format!("quota-5912/{filler}"))
        .execute(&pool)
        .await
        .unwrap();
        drop(state);
        Some(Self {
            pool,
            app,
            auth,
            user_id,
            repos,
            filler,
            _serial: serial,
        })
    }

    /// Put instance usage `over` bytes past the quota (negative: under it).
    async fn set_usage_relative_to_quota(&self, over: i64) {
        sqlx::query("UPDATE artifacts SET size_bytes = $2 WHERE id = $1")
            .bind(self.filler)
            .bind(4 * GIB + over)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    fn key(&self, i: usize) -> &str {
        &self.repos[i].1
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let reason = response
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !status.is_server_error(),
            "a quota path answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
        if status == StatusCode::FORBIDDEN {
            assert!(reason.is_some(), "a quota 403 carries its reason phrase");
        }
        (status, headers, body)
    }

    fn request(&self, method: Method, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, &self.auth)
            .body(body)
            .unwrap()
    }

    async fn teardown(self) {
        let ids: Vec<Uuid> = self.repos.iter().map(|r| r.0).collect();
        for table in ["oci_blobs", "artifacts"] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                "DELETE FROM {table} WHERE repository_id = ANY($1)"
            )))
            .bind(&ids)
            .execute(&self.pool)
            .await;
        }
        for (id, _, dir) in &self.repos {
            tdh::cleanup_member_repo(&self.pool, *id, dir).await;
        }
        tdh::cleanup_user(&self.pool, self.user_id).await;
        super::storage::install(&crate::config::QuotaSettings::default());
    }
}

/// A body that records whether anything polled it.
fn watched_body(polled: Arc<AtomicUsize>, bytes: &'static [u8]) -> Body {
    Body::from_stream(futures::stream::once(async move {
        polled.fetch_add(1, Ordering::SeqCst);
        Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(bytes))
    }))
}

fn json(body: &Bytes) -> Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("json body ({e}): {}", String::from_utf8_lossy(body)))
}

/// At the quota an upload is refused before its body is read; downloads,
/// listing and the quota read API keep working; and a delete makes room for
/// the next upload at once.
#[tokio::test]
async fn storage_quota_through_the_router_5912() {
    let Some(fx) = Fx::setup(&["maven"]).await else {
        return;
    };
    let jar = |name: &str| format!("/maven/{}/com/q5912/lib/1.0/{name}", fx.key(0));

    // Under the quota: a small upload is stored.
    let (status, _, body) = fx
        .send(fx.request(Method::PUT, &jar("lib-1.0.jar"), Body::from("jar-bytes")))
        .await;
    assert!(status.is_success(), "{status}: {body:?}");

    // A declared length over MAX_UPLOAD_SIZE is refused unread.
    let polled = Arc::new(AtomicUsize::new(0));
    let mut req = fx.request(
        Method::PUT,
        &jar("lib-1.0-huge.jar"),
        watched_body(polled.clone(), b"x"),
    );
    req.headers_mut().insert(
        header::CONTENT_LENGTH,
        (GIB + 4096).to_string().parse().unwrap(),
    );
    let (status, _, body) = fx.send(req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let body = json(&body);
    assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
    assert_eq!(body["limit_bytes"], MAX_UPLOAD);
    assert_eq!(body["content_length"], GIB + 4096);
    assert_eq!(
        polled.load(Ordering::SeqCst),
        0,
        "413 before the body is read"
    );

    // Over the quota: every write is refused before its body is read.
    fx.set_usage_relative_to_quota(GIB).await;
    let polled = Arc::new(AtomicUsize::new(0));
    let mut req = fx.request(
        Method::PUT,
        &jar("lib-1.0-b.jar"),
        watched_body(polled.clone(), b"jar"),
    );
    req.headers_mut()
        .insert(header::CONTENT_LENGTH, "3".parse().unwrap());
    let (status, _, body) = fx.send(req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        polled.load(Ordering::SeqCst),
        0,
        "403 before the body is read"
    );
    let body = json(&body);
    assert_eq!(body["code"], "STORAGE_QUOTA_EXCEEDED");
    assert_eq!(body["scope"], "instance");
    assert_eq!(body["help_url"], "https://quota.example.test/usage");
    let limit = body["limit_bytes"].as_u64().unwrap();
    let used = body["used_bytes"].as_u64().unwrap();
    assert!(used > limit, "{used} > {limit}");
    // ...and one without a length, refused once its size is known.
    let (status, _, body) = fx
        .send(fx.request(
            Method::PUT,
            &jar("lib-1.0-c.jar"),
            Body::from_stream(futures::stream::iter([Ok::<_, std::io::Error>(
                Bytes::from_static(b"chunked"),
            )])),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");

    // Downloads and reads still work.
    let (status, _, body) = fx
        .send(fx.request(Method::GET, &jar("lib-1.0.jar"), Body::empty()))
        .await;
    assert_eq!((status, &body[..]), (StatusCode::OK, &b"jar-bytes"[..]));
    let (status, _, body) = fx
        .send(fx.request(Method::GET, "/api/v1/system/quota", Body::empty()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let quota = json(&body);
    assert_eq!(quota["storage_quota"]["state"], "exceeded");
    assert_eq!(quota["storage_quota"]["enabled"], true);
    assert_eq!(quota["max_upload_bytes"], MAX_UPLOAD);
    assert_eq!(quota["quota_help_url"], "https://quota.example.test/usage");
    assert_eq!(quota["transfer_quota"]["enabled"], false);
    let (status, _, body) = fx
        .send(fx.request(Method::GET, "/api/v1/admin/stats", Body::empty()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["storage_quota"]["state"], "exceeded");
    // Anonymous callers do not get the figures.
    let anonymous = Request::get("/api/v1/system/quota")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        fx.app.clone().oneshot(anonymous).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // Deleting the filler frees its bytes at once: the next upload passes.
    let (status, _, body) = fx
        .send(fx.request(
            Method::DELETE,
            &format!(
                "/api/v1/repositories/{}/artifacts/filler/big.bin",
                fx.key(0)
            ),
            Body::empty(),
        ))
        .await;
    assert!(status.is_success(), "{status}: {body:?}");
    let (status, _, body) = fx
        .send(fx.request(Method::PUT, &jar("lib-1.0-b.jar"), Body::from("jar-2")))
        .await;
    assert!(status.is_success(), "{status}: {body:?}");

    fx.teardown().await;
}

/// `docker push` at the quota: a session already open is refused on its next
/// chunk and at completion, a new one at its start, all in the OCI envelope
/// and before any chunk body is read.
#[tokio::test]
async fn oci_chunked_push_is_refused_at_the_storage_quota_5912() {
    let Some(fx) = Fx::setup(&["docker"]).await else {
        return;
    };
    let uploads = format!("/v2/{}/app/blobs/uploads/", fx.key(0));
    let (status, headers, body) = fx
        .send(fx.request(Method::POST, &uploads, Body::empty()))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body:?}");
    let location = headers[header::LOCATION].to_str().unwrap().to_string();
    let (status, _, body) = fx
        .send(fx.request(Method::PATCH, &location, Body::from("chunk-1")))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body:?}");

    fx.set_usage_relative_to_quota(GIB).await;
    let refused = |body: &Bytes| {
        let body = json(body);
        assert_eq!(body["errors"][0]["code"], "DENIED", "{body}");
        assert_eq!(body["errors"][0]["detail"]["scope"], "instance");
        assert!(body["errors"][0]["message"]
            .as_str()
            .unwrap()
            .starts_with("Storage quota reached"));
    };
    let polled = Arc::new(AtomicUsize::new(0));
    let (status, _, body) = fx
        .send(fx.request(
            Method::PATCH,
            &location,
            watched_body(polled.clone(), b"chunk-2"),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    refused(&body);
    let digest = format!("sha256:{}", "ab".repeat(32));
    let complete = if location.contains('?') {
        format!("{location}&digest={digest}")
    } else {
        format!("{location}?digest={digest}")
    };
    let (status, _, body) = fx
        .send(fx.request(Method::PUT, &complete, Body::empty()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    refused(&body);
    let (status, _, body) = fx
        .send(fx.request(Method::POST, &uploads, Body::empty()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    refused(&body);
    let blobs: i64 = sqlx::query_scalar("SELECT count(*) FROM oci_blobs WHERE repository_id = $1")
        .bind(fx.repos[0].0)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(blobs, 0);

    fx.teardown().await;
}

/// `npm publish` at the quota answers the refusal with npm's `error` field.
#[tokio::test]
async fn npm_publish_refusal_carries_the_npm_error_field_5912() {
    let Some(fx) = Fx::setup(&["generic", "npm"]).await else {
        return;
    };
    fx.set_usage_relative_to_quota(GIB).await;
    let doc = {
        use base64::Engine;
        serde_json::json!({
            "name": "quota-pkg",
            "versions": { "1.0.0": { "name": "quota-pkg", "version": "1.0.0" } },
            "_attachments": {
                "quota-pkg-1.0.0.tgz": {
                    "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
                }
            }
        })
    };
    let mut req = fx.request(
        Method::PUT,
        &format!("/npm/{}/quota-pkg", fx.key(1)),
        Body::from(serde_json::to_vec(&doc).unwrap()),
    );
    req.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    let (status, _, body) = fx.send(req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let body = json(&body);
    assert_eq!(body["code"], "STORAGE_QUOTA_EXCEEDED");
    assert_eq!(body["error"], body["message"]);
    assert_eq!(body["scope"], "instance");

    fx.teardown().await;
}

/// The transfer quota through the router: downloads are counted, refused at
/// the hard limit with `Retry-After`, while uploads and metadata keep
/// working.
#[tokio::test]
async fn transfer_quota_through_the_router_5912() {
    let Some(fx) = Fx::setup(&["maven"]).await else {
        return;
    };
    // A fresh state with only a transfer quota (and no storage quota).
    let state = tdh::build_state_with(fx.pool.clone(), fx.repos[0].2.to_str().unwrap(), |c| {
        c.quotas.transfer_quota_bytes = 100;
        c.quotas.transfer_grace_percent = 20;
    });
    let app = crate::api::routes::create_router(state.clone());
    let send = |method: Method, uri: String, body: Body| {
        let app = app.clone();
        let auth = fx.auth.clone();
        async move {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, auth)
                .body(body)
                .unwrap();
            let response = app.oneshot(req).await.unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!status.is_server_error(), "{status}");
            (status, headers, body)
        }
    };
    let jar = format!("/maven/{}/com/t5912/lib/1.0/lib-1.0.jar", fx.key(0));
    let payload = vec![b'j'; 70];
    let (status, ..) = send(Method::PUT, jar.clone(), Body::from(payload.clone())).await;
    assert!(status.is_success(), "{status}");

    let (status, _, body) = send(Method::GET, jar.clone(), Body::empty()).await;
    assert_eq!((status, body.len()), (StatusCode::OK, 70));
    assert_eq!(state.transfer_meter.used_bytes(), 70);
    let (status, _, body) = send(Method::GET, jar.clone(), Body::empty()).await;
    assert_eq!(
        (status, body.len()),
        (StatusCode::OK, 70),
        "inside the grace band"
    );
    assert_eq!(state.transfer_meter.used_bytes(), 140);

    let (status, headers, body) = send(Method::GET, jar.clone(), Body::empty()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let expected = super::transfer::retry_after_secs(chrono::Utc::now());
    assert!(retry.abs_diff(expected) <= 5, "{retry} vs {expected}");
    let body = json(&body);
    assert_eq!(body["code"], "TRANSFER_QUOTA_EXCEEDED");
    assert_eq!(body["limit_bytes"], 100);
    assert_eq!(body["used_bytes"], 140);
    assert_eq!(body["retry_after_seconds"], retry);

    // Uploads, metadata and the API keep working.
    let (status, ..) = send(
        Method::PUT,
        format!("/maven/{}/com/t5912/lib/1.1/lib-1.1.jar", fx.key(0)),
        Body::from("more"),
    )
    .await;
    assert!(status.is_success(), "{status}");
    let (status, _, body) = send(
        Method::GET,
        "/api/v1/system/quota".to_string(),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let quota = json(&body);
    assert_eq!(quota["transfer_quota"]["state"], "refusing");
    assert_eq!(quota["transfer_quota"]["hard_limit_bytes"], 120);

    // The month's row is shared; clean it for the next run.
    let period = super::transfer::period_start(chrono::Utc::now());
    sqlx::query(
        "UPDATE transfer_quota_usage SET bytes = GREATEST(bytes - 140, 0) WHERE period_start = $1",
    )
    .bind(period)
    .execute(&fx.pool)
    .await
    .unwrap();
    fx.teardown().await;
}
