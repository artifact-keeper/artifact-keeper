//! The response every quota refusal answers with.
//!
//! One structured value, [`QuotaRefusal`], renders all of them: the backend's
//! standard error object (`code`, `message`) plus the figures a client or
//! the web UI needs to explain the refusal. [`super::http::quota_envelope`]
//! rewrites it into the native shape of the two formats whose clients only
//! read their own: the OCI error envelope on `/v2` and npm's `error` field.
//!
//! | Refusal | Status | `code` | OCI code |
//! |---|---|---|---|
//! | instance storage quota | 403 | `STORAGE_QUOTA_EXCEEDED` | `DENIED` |
//! | repository / project quota | 403 | `QUOTA_EXCEEDED` | `DENIED` |
//! | monthly transfer quota | 429 + `Retry-After` | `TRANSFER_QUOTA_EXCEEDED` | `TOOMANYREQUESTS` |
//! | upload size | 413 | `PAYLOAD_TOO_LARGE` | `SIZE_INVALID` |
//!
//! Why 403 for storage rather than 413 or 507: 413 means "this payload is too
//! large", which is false for a small package pushed into a full registry
//! (and some clients answer 413 by splitting and retrying); 507 is a 5xx,
//! which clients retry and monitoring reads as a server fault. 403 is a
//! refusal a client does not retry, and docker prints it as
//! `denied: <message>`. The `code` tells a quota refusal apart from a
//! permission refusal.
//!
//! Over HTTP/1.1 the response also carries a short reason phrase
//! (`403 Storage Quota Exceeded`), because Maven and twine print the reason
//! phrase rather than the body.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};

use super::format_bytes;
use crate::services::repository_service::{QuotaDenial, QuotaScope};

/// Which limit refused the request; also the `kind` label of
/// `ak_quota_refusals_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The instance-wide storage quota.
    Storage,
    /// A repository's (or its project's) storage quota.
    Repository,
    /// The monthly download transfer quota.
    Transfer,
    /// `MAX_UPLOAD_SIZE`.
    UploadSize,
}

impl RefusalKind {
    /// The metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Repository => "repository",
            Self::Transfer => "transfer",
            Self::UploadSize => "upload_size",
        }
    }
}

/// A quota refusal: everything its response body says.
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaRefusal {
    pub kind: RefusalKind,
    pub message: String,
    /// `instance`, `repository` or `project` for a storage refusal.
    pub scope: Option<&'static str>,
    pub repository: Option<String>,
    pub project: Option<String>,
    pub limit_bytes: u64,
    pub used_bytes: Option<u64>,
    /// The declared `Content-Length` of a refused upload, when known.
    pub content_length: Option<u64>,
    /// End of the transfer period (the start of the next one).
    pub period_end: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub help_url: Option<String>,
}

fn non_negative(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// `Some(upload)` when a refused write of `upload` bytes was refused only
/// because it does not fit in the space left (usage still below a finite
/// limit); `None` when the quota itself is reached or the size is unknown.
fn does_not_fit(limit: u64, used: u64, upload: Option<u64>) -> Option<u64> {
    upload.filter(|n| *n > 0 && used < limit)
}

impl QuotaRefusal {
    fn base(kind: RefusalKind, message: String, limit_bytes: u64) -> Self {
        Self {
            kind,
            message,
            scope: None,
            repository: None,
            project: None,
            limit_bytes,
            used_bytes: None,
            content_length: None,
            period_end: None,
            retry_after_seconds: None,
            help_url: None,
        }
    }

    /// The instance storage quota refuses a write.
    pub fn instance_storage(limit_bytes: u64, used_bytes: u64, help_url: Option<String>) -> Self {
        Self::instance_storage_write(limit_bytes, used_bytes, None, help_url)
    }

    /// The instance storage quota refuses a write that would add `upload`
    /// bytes (`None` when unknown). Below the quota the message says the
    /// upload does not fit in the space left, rather than that the quota is
    /// reached: smaller uploads still succeed.
    pub fn instance_storage_write(
        limit_bytes: u64,
        used_bytes: u64,
        upload: Option<u64>,
        help_url: Option<String>,
    ) -> Self {
        let message = match does_not_fit(limit_bytes, used_bytes, upload) {
            Some(upload) => format!(
                "This upload ({}) would exceed the storage quota: {} of {} used, {} free. \
                 Smaller uploads still fit; delete artifacts or raise the quota to upload \
                 this one. Downloads are not affected.",
                format_bytes(upload),
                format_bytes(used_bytes),
                format_bytes(limit_bytes),
                format_bytes(limit_bytes - used_bytes),
            ),
            None => format!(
                "{}: {} of {} used. Delete artifacts or raise the quota to upload again. \
                 Downloads are not affected.",
                QuotaScope::Instance.exceeded_message(),
                format_bytes(used_bytes),
                format_bytes(limit_bytes),
            ),
        };
        Self {
            scope: Some("instance"),
            used_bytes: Some(used_bytes),
            help_url,
            ..Self::base(RefusalKind::Storage, message, limit_bytes)
        }
    }

    /// This refusal with the refused request's declared `Content-Length`
    /// (`content_length` in the body), when known.
    pub fn with_content_length(mut self, content_length: Option<u64>) -> Self {
        self.content_length = content_length;
        self
    }

    /// The refusal a storage-quota denial answers with.
    pub fn from_denial(denial: &QuotaDenial) -> Self {
        let limit = non_negative(denial.limit_bytes);
        let used = non_negative(denial.used_bytes);
        match denial.scope {
            QuotaScope::Instance => Self::instance_storage_write(
                limit,
                used,
                denial.additional_bytes,
                super::storage::help_url(),
            ),
            QuotaScope::Repository | QuotaScope::Project => {
                let (scope, subject) = match denial.scope {
                    QuotaScope::Project => (
                        "project",
                        denial
                            .project
                            .as_deref()
                            .map(|p| format!("project '{p}'"))
                            .unwrap_or_else(|| "the project".to_string()),
                    ),
                    _ => (
                        "repository",
                        denial
                            .repository
                            .as_deref()
                            .map(|r| format!("repository '{r}'"))
                            .unwrap_or_else(|| "the repository".to_string()),
                    ),
                };
                let message = match does_not_fit(limit, used, denial.additional_bytes) {
                    Some(upload) => format!(
                        "This upload ({}) would exceed the storage quota of {subject}: it uses \
                         {} of its {} quota, {} free. Smaller uploads still fit; delete \
                         artifacts from it or raise its quota to upload this one. Downloads \
                         are not affected.",
                        format_bytes(upload),
                        format_bytes(used),
                        format_bytes(limit),
                        format_bytes(limit - used),
                    ),
                    None => format!(
                        "{}: {subject} uses {} of its {} quota. Delete artifacts from it or \
                         raise its quota to upload again. Downloads are not affected.",
                        denial.scope.exceeded_message(),
                        format_bytes(used),
                        format_bytes(limit),
                    ),
                };
                Self {
                    scope: Some(scope),
                    repository: denial.repository.clone(),
                    project: denial.project.clone(),
                    used_bytes: Some(used),
                    ..Self::base(RefusalKind::Repository, message, limit)
                }
            }
        }
    }

    /// The monthly transfer quota refuses a download.
    pub fn transfer(
        quota_bytes: u64,
        used_bytes: u64,
        period_end: DateTime<Utc>,
        retry_after_seconds: u64,
        help_url: Option<String>,
    ) -> Self {
        let message = format!(
            "Monthly download transfer quota reached: {} downloaded this month against a \
             quota of {}. Downloads resume on {} UTC or when the quota is raised. Uploads, \
             deletes and the API are not affected.",
            format_bytes(used_bytes),
            format_bytes(quota_bytes),
            period_end.format("%Y-%m-%d %H:%M"),
        );
        Self {
            used_bytes: Some(used_bytes),
            period_end: Some(period_end),
            retry_after_seconds: Some(retry_after_seconds),
            help_url,
            ..Self::base(RefusalKind::Transfer, message, quota_bytes)
        }
    }

    /// `MAX_UPLOAD_SIZE` refuses an upload.
    pub fn upload_size(limit_bytes: u64, content_length: Option<u64>) -> Self {
        let message = match content_length {
            Some(length) => format!(
                "Upload too large: the request body is {} but the upload limit is {}.",
                format_bytes(length),
                format_bytes(limit_bytes),
            ),
            None => format!(
                "Upload too large: the request body exceeds the upload limit of {}.",
                format_bytes(limit_bytes),
            ),
        };
        Self {
            content_length,
            ..Self::base(RefusalKind::UploadSize, message, limit_bytes)
        }
    }

    pub fn status(&self) -> StatusCode {
        match self.kind {
            RefusalKind::Storage | RefusalKind::Repository => StatusCode::FORBIDDEN,
            RefusalKind::Transfer => StatusCode::TOO_MANY_REQUESTS,
            RefusalKind::UploadSize => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    /// The machine-readable `code` of the standard error object.
    pub fn code(&self) -> &'static str {
        match self.kind {
            RefusalKind::Storage => "STORAGE_QUOTA_EXCEEDED",
            RefusalKind::Repository => "QUOTA_EXCEEDED",
            RefusalKind::Transfer => "TRANSFER_QUOTA_EXCEEDED",
            RefusalKind::UploadSize => "PAYLOAD_TOO_LARGE",
        }
    }

    /// The OCI distribution-spec error code.
    pub fn oci_code(&self) -> &'static str {
        match self.kind {
            RefusalKind::Storage | RefusalKind::Repository => "DENIED",
            RefusalKind::Transfer => "TOOMANYREQUESTS",
            RefusalKind::UploadSize => "SIZE_INVALID",
        }
    }

    /// The HTTP/1.1 reason phrase.
    pub fn reason_phrase(&self) -> &'static [u8] {
        match self.kind {
            RefusalKind::Storage => b"Storage Quota Exceeded",
            RefusalKind::Repository => b"Quota Exceeded",
            RefusalKind::Transfer => b"Transfer Quota Exceeded",
            RefusalKind::UploadSize => b"Payload Too Large",
        }
    }

    /// The fields after `code` and `message`: the OCI `detail` object, and
    /// the tail of the standard body.
    pub fn detail(&self) -> Map<String, Value> {
        let mut map = Map::new();
        if let Some(scope) = self.scope {
            map.insert("scope".into(), scope.into());
        }
        if let Some(repository) = &self.repository {
            map.insert("repository".into(), repository.clone().into());
        }
        if let Some(project) = &self.project {
            map.insert("project".into(), project.clone().into());
        }
        map.insert("limit_bytes".into(), self.limit_bytes.into());
        if let Some(used) = self.used_bytes {
            map.insert("used_bytes".into(), used.into());
        }
        if let Some(length) = self.content_length {
            map.insert("content_length".into(), length.into());
        }
        if let Some(end) = self.period_end {
            map.insert(
                "period_end".into(),
                end.to_rfc3339_opts(SecondsFormat::Secs, true).into(),
            );
        }
        if let Some(secs) = self.retry_after_seconds {
            map.insert("retry_after_seconds".into(), secs.into());
        }
        if let Some(url) = &self.help_url {
            map.insert("help_url".into(), url.clone().into());
        }
        map
    }

    /// The standard error object with the extra fields.
    pub fn body(&self) -> Value {
        let mut map = Map::new();
        map.insert("code".into(), self.code().into());
        map.insert("message".into(), self.message.clone().into());
        map.extend(self.detail());
        Value::Object(map)
    }

    /// The npm shape: the standard object plus `error`, which npm prints.
    pub fn npm_body(&self) -> Value {
        let mut body = self.body();
        if let Value::Object(map) = &mut body {
            map.insert("error".into(), self.message.clone().into());
        }
        body
    }

    /// The OCI error envelope.
    pub fn oci_body(&self) -> Value {
        serde_json::json!({
            "errors": [{
                "code": self.oci_code(),
                "message": self.message,
                "detail": Value::Object(self.detail()),
            }]
        })
    }

    /// A response with this refusal's status, headers and reason phrase and
    /// the given body. Carries the refusal as an extension so
    /// [`super::http::quota_envelope`] can re-render it for the route.
    pub fn response_with_body(&self, body: Value) -> Response {
        let mut response = (self.status(), Json(body)).into_response();
        if let Some(secs) = self.retry_after_seconds {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        if self.kind == RefusalKind::UploadSize {
            // The rest of the body is never read; do not reuse the connection.
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
            .extensions_mut()
            .insert(hyper::ext::ReasonPhrase::from_static(self.reason_phrase()));
        response.extensions_mut().insert(self.clone());
        response
    }
}

impl QuotaRefusal {
    /// Count (`ak_quota_refusals_total{kind}`) and log one refusal. Done by
    /// every rendering below; a format that renders its own native error
    /// (Connect) calls it directly.
    pub fn record(&self) {
        metrics::counter!("ak_quota_refusals_total", "kind" => self.kind.label()).increment(1);
        tracing::info!(
            code = self.code(),
            kind = self.kind.label(),
            limit_bytes = self.limit_bytes,
            used_bytes = ?self.used_bytes,
            repository = ?self.repository,
            "quota refusal"
        );
    }

    /// The refusal in the OCI error envelope, for the `/v2` handlers.
    pub fn into_oci_response(self) -> Response {
        self.record();
        self.response_with_body(self.oci_body())
    }
}

impl IntoResponse for QuotaRefusal {
    fn into_response(self) -> Response {
        self.record();
        self.response_with_body(self.body())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use http_body_util::BodyExt;

    const GIB: u64 = 1 << 30;

    pub(crate) async fn json_of(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).expect("json body"))
    }

    #[tokio::test]
    async fn instance_storage_refusal_is_a_403_with_the_contract_fields() {
        let refusal = QuotaRefusal::instance_storage(
            10 * GIB,
            10 * GIB,
            Some("https://example.test/usage".into()),
        );
        let response = refusal.into_response();
        assert_eq!(
            response
                .extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .map(|r| r.as_bytes().to_vec()),
            Some(b"Storage Quota Exceeded".to_vec())
        );
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            serde_json::json!({
                "code": "STORAGE_QUOTA_EXCEEDED",
                "message": "Storage quota reached: 10.0 GiB of 10.0 GiB used. Delete artifacts \
                            or raise the quota to upload again. Downloads are not affected.",
                "scope": "instance",
                "limit_bytes": 10 * GIB,
                "used_bytes": 10 * GIB,
                "help_url": "https://example.test/usage",
            })
        );
    }

    #[tokio::test]
    async fn repository_and_project_denials_name_their_subject() {
        let mut denial = QuotaDenial::new(QuotaScope::Repository, 100, 60);
        denial.repository = Some("libs".into());
        let (status, body) = json_of(denial.refusal().into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "QUOTA_EXCEEDED");
        assert_eq!(body["scope"], "repository");
        assert_eq!(body["repository"], "libs");
        assert_eq!(body["limit_bytes"], 100);
        assert_eq!(body["used_bytes"], 60);
        assert!(body.get("help_url").is_none());
        assert!(body["message"]
            .as_str()
            .unwrap()
            .starts_with("Repository storage quota exceeded: repository 'libs' uses 60 bytes"));

        let mut denial = QuotaDenial::new(QuotaScope::Project, 100, 90);
        denial.repository = Some("libs".into());
        denial.project = Some("team".into());
        let refusal = denial.refusal();
        assert_eq!(refusal.kind, RefusalKind::Repository);
        assert_eq!(refusal.body()["scope"], "project");
        assert_eq!(refusal.body()["project"], "team");
        assert!(refusal
            .message
            .starts_with("Project storage quota exceeded: project 'team'"));
        assert!(matches!(
            denial.into_error(),
            crate::error::AppError::QuotaRefused(_)
        ));
    }

    #[tokio::test]
    async fn an_upload_that_does_not_fit_says_so_below_the_quota() {
        const MIB: u64 = 1 << 20;
        // 97.5 % used, a 256 MiB upload: refused because it does not fit,
        // not because the quota is reached.
        let used = 10 * GIB - 256 * MIB;
        let refusal = QuotaRefusal::instance_storage_write(10 * GIB, used, Some(512 * MIB), None)
            .with_content_length(Some(512 * MIB));
        let (status, body) = json_of(refusal.into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            serde_json::json!({
                "code": "STORAGE_QUOTA_EXCEEDED",
                "message": "This upload (512.0 MiB) would exceed the storage quota: 9.8 GiB of \
                            10.0 GiB used, 256.0 MiB free. Smaller uploads still fit; delete \
                            artifacts or raise the quota to upload this one. Downloads are not \
                            affected.",
                "scope": "instance",
                "limit_bytes": 10 * GIB,
                "used_bytes": used,
                "content_length": 512 * MIB,
            })
        );

        // At the quota the size does not matter: the quota is reached.
        for upload in [Some(1), Some(GIB), None] {
            let at = QuotaRefusal::instance_storage_write(10 * GIB, 10 * GIB, upload, None);
            assert!(at
                .message
                .starts_with("Storage quota reached: 10.0 GiB of 10.0 GiB used."));
        }
        // An unknown or empty size keeps the reached wording, and no
        // content_length is invented.
        let unknown =
            QuotaRefusal::instance_storage_write(100, 60, None, None).with_content_length(None);
        assert!(unknown.message.starts_with("Storage quota reached"));
        assert!(unknown.body().get("content_length").is_none());
        assert!(QuotaRefusal::instance_storage_write(100, 60, Some(0), None)
            .message
            .starts_with("Storage quota reached"));

        // The same from an instance denial that knows the write's size.
        let denial = QuotaDenial::new(QuotaScope::Instance, 100, 60).with_additional(41);
        assert!(denial.refusal().message.starts_with(
            "This upload (41 bytes) would exceed the storage quota: 60 bytes of \
                          100 bytes used, 40 bytes free."
        ));
    }

    #[test]
    fn a_repository_upload_that_does_not_fit_says_so_below_its_quota() {
        let mut denial = QuotaDenial::new(QuotaScope::Repository, 100, 60).with_additional(50);
        denial.repository = Some("libs".into());
        let refusal = denial.refusal();
        assert_eq!(refusal.code(), "QUOTA_EXCEEDED");
        assert_eq!(
            refusal.message,
            "This upload (50 bytes) would exceed the storage quota of repository 'libs': it \
             uses 60 bytes of its 100 bytes quota, 40 bytes free. Smaller uploads still fit; \
             delete artifacts from it or raise its quota to upload this one. Downloads are not \
             affected."
        );
        let refusal = refusal.with_content_length(Some(50));
        assert_eq!(refusal.body()["content_length"], 50);
        assert_eq!(refusal.body()["used_bytes"], 60);

        let mut denial = QuotaDenial::new(QuotaScope::Project, 100, 100).with_additional(1);
        denial.project = Some("team".into());
        assert!(denial
            .refusal()
            .message
            .starts_with("Project storage quota exceeded: project 'team' uses 100 bytes"));
        // A non-positive size is not recorded.
        assert_eq!(
            QuotaDenial::new(QuotaScope::Repository, 1, 1)
                .with_additional(-5)
                .additional_bytes,
            None
        );
    }

    #[tokio::test]
    async fn transfer_refusal_is_a_429_with_retry_after() {
        let end = Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap();
        let refusal = QuotaRefusal::transfer(50 * GIB, 63 * GIB, end, 3600, None);
        let response = refusal.into_response();
        assert_eq!(response.headers()[header::RETRY_AFTER], "3600");
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "TRANSFER_QUOTA_EXCEEDED");
        assert_eq!(body["period_end"], "2026-12-01T00:00:00Z");
        assert_eq!(body["retry_after_seconds"], 3600);
        assert_eq!(body["limit_bytes"], 50 * GIB);
        assert_eq!(body["used_bytes"], 63 * GIB);
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("Downloads resume on 2026-12-01 00:00 UTC"));
    }

    #[tokio::test]
    async fn upload_size_refusal_is_a_413_and_closes_the_connection() {
        let response = QuotaRefusal::upload_size(2 * GIB, Some(3 * GIB)).into_response();
        assert_eq!(response.headers()[header::CONNECTION], "close");
        let (status, body) = json_of(response).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
        assert_eq!(body["limit_bytes"], 2 * GIB);
        assert_eq!(body["content_length"], 3 * GIB);
        let without = QuotaRefusal::upload_size(10, None).body();
        assert!(without.get("content_length").is_none());
    }

    #[test]
    fn format_envelopes_carry_the_same_fields() {
        let refusal = QuotaRefusal::instance_storage(100, 100, None);
        let oci = refusal.oci_body();
        assert_eq!(oci["errors"][0]["code"], "DENIED");
        assert_eq!(oci["errors"][0]["message"], refusal.message.as_str());
        assert_eq!(oci["errors"][0]["detail"]["limit_bytes"], 100);
        assert_eq!(oci["errors"][0]["detail"]["scope"], "instance");
        let npm = refusal.npm_body();
        assert_eq!(npm["error"], refusal.message.as_str());
        assert_eq!(npm["code"], "STORAGE_QUOTA_EXCEEDED");
        for (kind, oci_code, status) in [
            (RefusalKind::Transfer, "TOOMANYREQUESTS", 429),
            (RefusalKind::UploadSize, "SIZE_INVALID", 413),
            (RefusalKind::Repository, "DENIED", 403),
        ] {
            let r = QuotaRefusal {
                kind,
                ..refusal.clone()
            };
            assert_eq!(r.oci_code(), oci_code);
            assert_eq!(r.status().as_u16(), status);
            assert!(!r.status().is_server_error());
        }
    }

    #[test]
    fn refusals_are_counted_by_kind() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let _ = QuotaRefusal::upload_size(1, None).into_response();
        let _ = QuotaRefusal::upload_size(1, None).into_response();
        let counted: Vec<(String, u64)> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| key.key().name() == "ak_quota_refusals_total")
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Counter(n) => Some((
                    key.key()
                        .labels()
                        .find(|l| l.key() == "kind")
                        .map(|l| l.value().to_string())
                        .unwrap_or_default(),
                    n,
                )),
                _ => None,
            })
            .collect();
        assert_eq!(counted, vec![("upload_size".to_string(), 2)]);
    }
}
