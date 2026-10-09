//! Admission and progress limits for artifact byte transfers
//! (GHSA-9f9r-c4w8-rjv9).
//!
//! Byte-transfer routes ([`crate::api::routes::is_byte_transfer_path`]) are
//! exempt from the router-wide wall-clock timeout (#3263), because that clock
//! also covers the time a client spends uploading, and on a slow link it turns
//! into a size cap. Without some other bound, a writer could open many uploads,
//! send the headers and one byte, and hold every global request permit
//! indefinitely. This module supplies the bounds that do not depend on body size:
//!
//! * [`upload_progress_deadline`]: an upload body must deliver at least
//!   `min_progress_bytes` in every `progress_window` it spends waiting for
//!   data, or the request fails with `408 Request Timeout`. This is a
//!   progress deadline, not an idle timeout. A client that trickles one byte
//!   per window does not keep the request alive. Any real upload on any real
//!   link clears the default floor (16 KiB per 60 s) easily.
//! * [`per_principal_upload_admission`]: at most `max_in_flight` concurrent
//!   uploads per principal (the authenticated user, or the client address for
//!   an anonymous caller). The rest are refused with `429` and `Retry-After`,
//!   so one credential cannot take the whole global pool.
//!
//! The global pool itself, and the health/readiness exemption from it, live in
//! [`crate::api::routes`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body::{Frame, SizeHint};

use crate::api::middleware::auth::AuthExtension;

/// The progress requirement on an upload body.
#[derive(Debug, Clone, Copy)]
pub struct ProgressPolicy {
    /// How long a body may wait for data before it must have delivered
    /// `min_progress_bytes` since the window opened.
    pub window: Duration,
    /// Bytes the body must deliver per window.
    pub min_progress_bytes: u64,
}

impl ProgressPolicy {
    /// The policy configured by `UPLOAD_PROGRESS_WINDOW_SECS` and
    /// `UPLOAD_MIN_PROGRESS_BYTES`, or `None` when the window is 0
    /// (disabled).
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        (config.upload_progress_window_secs > 0).then(|| Self {
            window: Duration::from_secs(config.upload_progress_window_secs),
            min_progress_bytes: config.upload_min_progress_bytes,
        })
    }
}

/// The error a stalled body yields. Handlers see it as a body read failure.
/// The middleware turns the response into a 408, whatever the handler made of
/// the failure.
#[derive(Debug)]
pub struct UploadStalled;

impl std::fmt::Display for UploadStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upload body made no progress within the upload progress window")
    }
}

impl std::error::Error for UploadStalled {}

/// A request body that fails with [`UploadStalled`] when it delivers fewer
/// than `min_progress_bytes` during a `window` spent waiting for data.
///
/// The window opens lazily, the first time the body is polled and has nothing
/// ready, so time a handler spends before it reads the body (auth, database
/// lookups) does not count against the client. It closes, and the count
/// resets, once enough bytes have arrived. Size hints and end-of-stream are
/// passed through unchanged, so handlers that look at them behave as before.
pub struct ProgressDeadlineBody<B> {
    inner: B,
    policy: ProgressPolicy,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    received_in_window: u64,
    stalled: Arc<AtomicBool>,
}

impl<B> ProgressDeadlineBody<B> {
    pub fn new(inner: B, policy: ProgressPolicy, stalled: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            policy,
            deadline: None,
            received_in_window: 0,
            stalled,
        }
    }
}

impl<B> http_body::Body for ProgressDeadlineBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<axum::BoxError>,
{
    type Data = Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.received_in_window =
                        this.received_in_window.saturating_add(data.len() as u64);
                    if this.received_in_window >= this.policy.min_progress_bytes {
                        // Enough progress: close the window. The next wait
                        // opens a fresh one.
                        this.deadline = None;
                        this.received_in_window = 0;
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                let window = this.policy.window;
                let deadline = this
                    .deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(window)));
                match deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.stalled.store(true, Ordering::Release);
                        Poll::Ready(Some(Err(Box::new(UploadStalled))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Whether `method` carries an upload body worth guarding.
fn is_upload_method(method: &Method) -> bool {
    matches!(*method, Method::PUT | Method::POST | Method::PATCH)
}

/// The full request path, also inside a nested router.
fn full_path(req: &Request) -> String {
    req.extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string())
}

fn stalled_response() -> Response {
    let mut response = (
        StatusCode::REQUEST_TIMEOUT,
        "Upload stalled: the request body made too little progress",
    )
        .into_response();
    // The rest of the body is never read; do not keep the connection.
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    response
}

/// Router-wide middleware: give every byte-transfer upload body a progress
/// deadline ([`ProgressDeadlineBody`]), and answer `408` when it fires.
pub async fn upload_progress_deadline(
    State(policy): State<ProgressPolicy>,
    req: Request,
    next: Next,
) -> Response {
    if !is_upload_method(req.method())
        || !crate::api::routes::is_byte_transfer_path(&full_path(&req))
    {
        return next.run(req).await;
    }
    let stalled = Arc::new(AtomicBool::new(false));
    let (parts, body) = req.into_parts();
    let body = Body::new(ProgressDeadlineBody::new(body, policy, stalled.clone()));
    let response = next.run(Request::from_parts(parts, body)).await;
    if stalled.load(Ordering::Acquire) {
        tracing::warn!(
            target: "security",
            "upload aborted: request body made too little progress (GHSA-9f9r-c4w8-rjv9)"
        );
        return stalled_response();
    }
    response
}

/// Per-principal count of in-flight uploads.
#[derive(Debug, Default)]
pub struct UploadAdmission {
    max_in_flight: usize,
    in_flight: Mutex<HashMap<String, usize>>,
}

/// One admitted upload. Dropping it frees the principal's slot.
#[derive(Debug)]
pub struct AdmissionSlot {
    admission: Arc<UploadAdmission>,
    key: String,
}

impl Drop for AdmissionSlot {
    fn drop(&mut self) {
        let mut map = self
            .admission
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl UploadAdmission {
    /// `max_in_flight` uploads per principal; 0 admits everything.
    pub fn new(max_in_flight: usize) -> Arc<Self> {
        Arc::new(Self {
            max_in_flight,
            in_flight: Mutex::new(HashMap::new()),
        })
    }

    /// Admit one more upload for `key`, or `None` when it is at its limit.
    pub fn try_admit(self: &Arc<Self>, key: &str) -> Option<AdmissionSlot> {
        let mut map = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(key.to_string()).or_insert(0);
        if self.max_in_flight != 0 && *n >= self.max_in_flight {
            return None;
        }
        *n += 1;
        Some(AdmissionSlot {
            admission: Arc::clone(self),
            key: key.to_string(),
        })
    }

    /// Uploads currently in flight for `key`.
    pub fn in_flight(&self, key: &str) -> usize {
        self.in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .copied()
            .unwrap_or(0)
    }
}

/// The admission key for a request: the authenticated user, else the client
/// address, else one shared anonymous bucket.
pub fn principal_key(auth: Option<&AuthExtension>) -> String {
    match auth {
        Some(a) => format!("user:{}", a.user_id),
        None => match crate::api::middleware::client_ip::current_client_ip() {
            Some(ip) => format!("anon:{ip}"),
            None => "anon".to_string(),
        },
    }
}

/// Middleware for routers whose authentication middleware has already run
/// (it reads the `Option<AuthExtension>` those insert): refuse a byte-transfer
/// upload with `429` when its principal already has `max_in_flight` in
/// flight, and hold the slot until the handler returns.
pub async fn per_principal_upload_admission(
    State(admission): State<Arc<UploadAdmission>>,
    req: Request,
    next: Next,
) -> Response {
    if admission.max_in_flight == 0
        || !is_upload_method(req.method())
        || !crate::api::routes::is_byte_transfer_path(&full_path(&req))
    {
        return next.run(req).await;
    }
    let auth = req
        .extensions()
        .get::<Option<AuthExtension>>()
        .cloned()
        .flatten();
    let key = principal_key(auth.as_ref());
    let Some(_slot) = admission.try_admit(&key) else {
        tracing::warn!(
            target: "security",
            principal = %key,
            limit = admission.max_in_flight,
            "upload refused: principal is at its in-flight upload limit (GHSA-9f9r-c4w8-rjv9)"
        );
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many concurrent uploads for this principal; retry when one finishes",
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("5"));
        return response;
    };
    next.run(req).await
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, put};
    use axum::Router;
    use futures::StreamExt;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn policy(window_ms: u64, min: u64) -> ProgressPolicy {
        ProgressPolicy {
            window: Duration::from_millis(window_ms),
            min_progress_bytes: min,
        }
    }

    /// One chunk, then nothing, forever: the advisory's "headers and one
    /// body byte" upload.
    fn one_byte_then_silence() -> Body {
        Body::from_stream(
            futures::stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"x")) })
                .chain(futures::stream::pending()),
        )
    }

    /// One byte every `every_ms`, forever: a client trying to look alive.
    fn trickle(every_ms: u64) -> Body {
        Body::from_stream(futures::stream::unfold((), move |()| async move {
            tokio::time::sleep(Duration::from_millis(every_ms)).await;
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"x")), ()))
        }))
    }

    async fn drain(body: ProgressDeadlineBody<Body>) -> Result<usize, axum::BoxError> {
        let mut body = body;
        let mut n = 0;
        while let Some(frame) = body.frame().await {
            if let Some(data) = frame?.data_ref() {
                n += data.len();
            }
        }
        Ok(n)
    }

    #[tokio::test]
    async fn a_silent_body_fails_after_one_window() {
        let stalled = Arc::new(AtomicBool::new(false));
        let body =
            ProgressDeadlineBody::new(one_byte_then_silence(), policy(50, 1024), stalled.clone());
        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(5), drain(body))
            .await
            .expect("the deadline must fire, not hang")
            .expect_err("a silent body must fail");
        assert!(err.is::<UploadStalled>(), "{err}");
        assert!(stalled.load(Ordering::Acquire));
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn a_trickle_below_the_floor_still_fails() {
        let stalled = Arc::new(AtomicBool::new(false));
        // 1 byte per 10 ms against a floor of 1 KiB per 100 ms.
        let body = ProgressDeadlineBody::new(trickle(10), policy(100, 1024), stalled.clone());
        let err = tokio::time::timeout(Duration::from_secs(5), drain(body))
            .await
            .expect("a trickle must not keep the body alive")
            .expect_err("a trickle below the floor must fail");
        assert!(err.is::<UploadStalled>(), "{err}");
    }

    #[tokio::test]
    async fn a_body_that_makes_progress_completes_and_keeps_its_size_hint() {
        let stalled = Arc::new(AtomicBool::new(false));
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            (0..8).map(|_| Ok(Bytes::from(vec![7u8; 4096]))).collect();
        let slow = futures::stream::iter(chunks).then(|c| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            c
        });
        let body =
            ProgressDeadlineBody::new(Body::from_stream(slow), policy(100, 1024), stalled.clone());
        assert_eq!(drain(body).await.expect("progressing body"), 8 * 4096);
        assert!(!stalled.load(Ordering::Acquire));

        let sized = ProgressDeadlineBody::new(Body::from("abc"), policy(100, 1024), stalled);
        assert_eq!(http_body::Body::size_hint(&sized).exact(), Some(3));
    }

    fn upload_app(window_ms: u64) -> Router {
        Router::new()
            .route(
                "/lfs/r/objects/:oid",
                put(|body: Bytes| async move { format!("got {}", body.len()) }),
            )
            .route(
                "/api/v1/other",
                put(|body: Bytes| async move { format!("{}", body.len()) }),
            )
            .layer(axum::middleware::from_fn_with_state(
                policy(window_ms, 1024),
                upload_progress_deadline,
            ))
    }

    fn put_req(path: &str, body: Body) -> Request {
        axum::http::Request::builder()
            .method(Method::PUT)
            .uri(path)
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn a_stalled_byte_transfer_upload_gets_408_and_a_closed_connection() {
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            upload_app(50).oneshot(put_req("/lfs/r/objects/abc", one_byte_then_silence())),
        )
        .await
        .expect("must not hang")
        .unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            resp.headers().get(header::CONNECTION).map(|v| v.as_bytes()),
            Some(&b"close"[..])
        );

        let ok = upload_app(50)
            .oneshot(put_req("/lfs/r/objects/abc", Body::from(vec![1u8; 10])))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_byte_transfer_routes_are_left_to_the_wall_clock_timeout() {
        // Not wrapped: with no data the handler simply keeps waiting, which
        // the router-wide request timeout bounds on these routes.
        let pending = upload_app(50).oneshot(put_req("/api/v1/other", one_byte_then_silence()));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), pending)
                .await
                .is_err(),
            "the progress deadline applies to byte-transfer routes only"
        );
    }

    #[test]
    fn admission_counts_per_principal_and_frees_on_drop() {
        let admission = UploadAdmission::new(2);
        let a1 = admission.try_admit("user:a").expect("first");
        let a2 = admission.try_admit("user:a").expect("second");
        assert!(
            admission.try_admit("user:a").is_none(),
            "third is over the cap"
        );
        let b1 = admission
            .try_admit("user:b")
            .expect("another principal is independent");
        assert_eq!(admission.in_flight("user:a"), 2);
        drop(a1);
        assert_eq!(admission.in_flight("user:a"), 1);
        let a3 = admission
            .try_admit("user:a")
            .expect("a freed slot is reusable");
        drop((a2, a3, b1));
        assert_eq!(admission.in_flight("user:a"), 0);
        assert!(
            admission.in_flight.lock().unwrap().is_empty(),
            "no leaked keys"
        );

        let open = UploadAdmission::new(0);
        let held: Vec<_> = (0..100).map(|_| open.try_admit("k").unwrap()).collect();
        assert_eq!(held.len(), 100, "0 disables the cap");
    }

    #[test]
    fn principal_key_prefers_the_authenticated_user() {
        let user = uuid::Uuid::new_v4();
        let auth = AuthExtension {
            user_id: user,
            username: "u".into(),
            email: "u@test.local".into(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        assert_eq!(principal_key(Some(&auth)), format!("user:{user}"));
        assert_eq!(principal_key(None), "anon");
    }

    #[tokio::test]
    async fn the_admission_middleware_refuses_the_principal_over_its_cap() {
        let release = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let (hold, held) = (release.clone(), entered.clone());
        let admission = UploadAdmission::new(1);
        let user = |id: uuid::Uuid| AuthExtension {
            user_id: id,
            username: "u".into(),
            email: "u@test.local".into(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        let app = |who: AuthExtension| {
            let (hold, held) = (hold.clone(), held.clone());
            Router::new()
                .route(
                    "/lfs/r/objects/:oid",
                    put(move || {
                        let (hold, held) = (hold.clone(), held.clone());
                        async move {
                            held.add_permits(1);
                            hold.notified().await;
                            "stored"
                        }
                    }),
                )
                .route("/health", get(|| async { "ok" }))
                .layer(axum::middleware::from_fn_with_state(
                    admission.clone(),
                    per_principal_upload_admission,
                ))
                .layer(axum::Extension(Some(who)))
        };
        let (alice, bob) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let first =
            tokio::spawn(app(user(alice)).oneshot(put_req("/lfs/r/objects/1", Body::from("a"))));
        entered.acquire().await.unwrap().forget();

        let refused = app(user(alice))
            .oneshot(put_req("/lfs/r/objects/2", Body::from("a")))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(refused.headers().contains_key(header::RETRY_AFTER));

        let other =
            tokio::spawn(app(user(bob)).oneshot(put_req("/lfs/r/objects/3", Body::from("b"))));
        entered.acquire().await.unwrap().forget();

        release.notify_waiters();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(other.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(admission.in_flight(&format!("user:{alice}")), 0);
    }
}
