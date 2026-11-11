//! The job loop: claim from the backend, run, post the result.
//!
//! The worker holds no database or storage credentials: it talks to the
//! backend's HTTP API with one API token carrying the `mcp:introspect`
//! scope. Jobs run one at a time, which also caps per-host concurrency at
//! one.

use std::time::Duration;

use serde_json::{json, Value};

use crate::http::{check_url, HttpTransport};
use crate::protocol::{probe, ProbeReport};
use crate::sandbox::{guest_spec, run_and_probe, Images, SandboxError, SandboxRunner};

use artifact_keeper_backend::services::mcp_capabilities as caps;

/// The backend's limits, so a result the backend would refuse is refused
/// here, with the reason, instead of being posted, rejected, and left to
/// expire as "claim lease expired".
pub const MAX_ITEMS: usize = caps::MAX_ITEMS;
pub const MAX_BYTES: usize = caps::INGEST_MAX_BYTES;
/// The whole remote probe (all requests together).
pub const REMOTE_BUDGET: Duration = Duration::from_secs(30);

/// The backend's worker API.
pub struct Backend {
    client: reqwest::Client,
    base: String,
    token: String,
}

impl Backend {
    /// `base` is the operator-configured AK URL (trusted configuration, so
    /// not run through the public-range guard the probe uses).
    /// The backend may sit behind the deployment's proxy, so the process
    /// proxy settings apply (unlike the probe's guarded client).
    pub fn new(base: &str, token: &str) -> Self {
        Self::with_builder(base, token, Self::builder())
    }

    fn builder() -> reqwest::ClientBuilder {
        artifact_keeper_backend::services::http_client::plain_client_builder()
            .user_agent(crate::http::user_agent())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
    }

    /// A backend reached without the process proxy settings: tests talk to
    /// a local mock, which a `HTTP_PROXY` in the environment must not
    /// redirect.
    #[cfg(test)]
    fn direct(base: &str, token: &str) -> Self {
        Self::with_builder(base, token, Self::builder().no_proxy())
    }

    fn with_builder(base: &str, token: &str, builder: reqwest::ClientBuilder) -> Self {
        let client = builder.build().expect("HTTP client");
        Self {
            client,
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let resp = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("backend unreachable: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// `None` when nothing is due (204).
    pub async fn claim(&self, kinds: &[&str], worker_id: &str) -> Result<Option<Value>, String> {
        let (status, body) = self
            .post(
                "/api/v1/mcp/introspection/jobs/claim",
                &json!({"kinds": kinds, "workerId": worker_id}),
            )
            .await?;
        match status {
            200 => Ok(Some(body)),
            204 => Ok(None),
            s => Err(format!("claim refused ({s}): {body}")),
        }
    }

    pub async fn complete(&self, job_id: &str, result: &Value) -> Result<Value, String> {
        let (status, body) = self
            .post(
                &format!("/api/v1/mcp/introspection/jobs/{job_id}/complete"),
                result,
            )
            .await?;
        match status {
            200 => Ok(body),
            // A refused result names the field (#5466): say which, so a
            // result that would be refused on every attempt is diagnosable.
            400 => {
                let (code, field) = (
                    body["error"].as_str().unwrap_or(""),
                    body["field"].as_str().unwrap_or(""),
                );
                tracing::warn!(job = %job_id, %code, %field, "introspection result refused");
                Err(format!(
                    "complete refused (400 {code}, field `{field}`): {body}"
                ))
            }
            _ => Err(format!("complete refused ({status}): {body}")),
        }
    }

    /// `POST .../capabilities` with a converted inventory.
    pub async fn push(
        &self,
        repo: &str,
        server: &str,
        version: &str,
        body: &Value,
    ) -> Result<Value, String> {
        let path = format!(
            "/mcp/{}/v0.1/servers/{}/versions/{}/capabilities",
            urlencoding::encode(repo),
            urlencoding::encode(server),
            urlencoding::encode(version)
        );
        let (status, resp) = self.post(&path, body).await?;
        if status == 201 {
            Ok(resp)
        } else {
            Err(format!("report refused ({status}): {resp}"))
        }
    }
}

pub struct Worker {
    pub backend: Backend,
    pub worker_id: String,
    /// `None`: this worker does not run sandbox jobs.
    pub runner: Option<Box<dyn SandboxRunner>>,
    pub images: Images,
    pub http: reqwest::Client,
}

fn failed(outcome: &str, error: impl Into<String>) -> ProbeReport {
    ProbeReport {
        outcome: outcome.into(),
        auth_state: "none".into(),
        error: Some(error.into()),
        ..Default::default()
    }
}

/// `report` as the backend will accept it: an `ok` result whose lists or
/// instructions break the backend's limits ([`caps::CapabilitySet::from_doc`],
/// the same check the backend applies) becomes `refused` with the reason.
pub fn within_backend_limits(report: ProbeReport) -> ProbeReport {
    if report.outcome != "ok" {
        return report;
    }
    let doc = json!({
        "tools": report.tools, "resources": report.resources,
        "prompts": report.prompts, "instructions": report.instructions,
    });
    match caps::CapabilitySet::from_doc(&doc) {
        Ok(_) => report,
        Err(e) => ProbeReport {
            details: report.details,
            ..failed("refused", format!("result over the backend's limits: {e}"))
        },
    }
}

/// A `complete` body the backend accepts: within its request body limit
/// ([`MAX_BYTES`]), else the result is replaced by a `refused` one.
pub fn within_body_limit(body: Value) -> Value {
    let size = serde_json::to_vec(&body)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size <= MAX_BYTES {
        return body;
    }
    let mut r = failed(
        "refused",
        format!("result is {size} bytes, over the backend's {MAX_BYTES} byte limit"),
    )
    .to_result_json();
    for k in ["claimToken", "workerVersion"] {
        r[k] = body[k].clone();
    }
    r
}

/// Probe one remote URL with the guard, the cap and the overall budget.
pub async fn probe_remote(client: reqwest::Client, url: &str) -> ProbeReport {
    if let Err(e) = check_url(url) {
        return failed("refused", format!("target refused: {e}"));
    }
    let mut t = HttpTransport::new(client, url, MAX_BYTES);
    match tokio::time::timeout(REMOTE_BUDGET, probe(&mut t, MAX_ITEMS)).await {
        Ok(r) => within_backend_limits(r),
        Err(_) => failed("timeout", "probe exceeded 30 s"),
    }
}

/// Run one sandbox job (`target` as a claimed job carries it) with `runner`
/// and probe the guest over its stdio. Shared by the job loop and the
/// backend-free `sandbox-probe` subcommand.
pub async fn sandbox_probe(
    runner: &dyn SandboxRunner,
    images: &Images,
    job_id: &str,
    target: &Value,
    ak_base_url: &str,
) -> ProbeReport {
    match guest_spec(job_id, target, ak_base_url, images)
        .and_then(|spec| runner.plan(&spec).map(|p| (spec, p)))
    {
        Ok((spec, plan)) => {
            let mut r = run_and_probe(&plan, MAX_ITEMS, MAX_BYTES).await;
            r.details.insert("runner".into(), json!(runner.name()));
            r.details.insert("image".into(), json!(spec.image));
            r.details.insert("notes".into(), json!(spec.notes));
            within_backend_limits(r)
        }
        // The deployment, not the server: retried (`start_failed` is
        // transient), never stored as the server's state.
        Err(e @ SandboxError::Deployment(_)) => failed("start_failed", e.to_string()),
        Err(e) => failed("unsupported", e.to_string()),
    }
}

/// How often an idle worker removes guests and guest networks that leaked
/// (a cleanup command failed or timed out), besides once at startup.
pub const REAP_EVERY: Duration = Duration::from_secs(600);

impl Worker {
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut k = vec!["remote_probe"];
        if self.runner.is_some() {
            k.push("sandbox_run");
        }
        k
    }

    /// Run one claimed job; the returned body is the `complete` request.
    pub async fn run_job(&self, job: &Value) -> Value {
        let target = &job["target"];
        let report = match job["kind"].as_str() {
            Some("remote_probe") => match target["url"].as_str() {
                Some(url) => probe_remote(self.http.clone(), url).await,
                None => failed("error", "job has no URL"),
            },
            Some("sandbox_run") => match &self.runner {
                None => failed("unsupported", "this worker does not run sandbox jobs"),
                Some(runner) => {
                    let ak = job["akBaseUrl"].as_str().unwrap_or(self.backend.base());
                    let job_id = job["jobId"].as_str().unwrap_or("job");
                    sandbox_probe(runner.as_ref(), &self.images, job_id, target, ak).await
                }
            },
            _ => failed("unsupported", "unknown job kind"),
        };
        let mut body = within_backend_limits(report).to_result_json();
        body["claimToken"] = job["claimToken"].clone();
        body["workerVersion"] = json!(format!(
            "ak-mcp-introspector/{}",
            artifact_keeper_backend::build_info::VERSION
        ));
        within_body_limit(body)
    }

    /// Claim and run at most one job. `Ok(true)` when one ran.
    pub async fn once(&self) -> Result<bool, String> {
        let Some(job) = self.backend.claim(&self.kinds(), &self.worker_id).await? else {
            return Ok(false);
        };
        let id = job["jobId"].as_str().unwrap_or_default().to_string();
        let result = self.run_job(&job).await;
        tracing::info!(
            job = %id,
            kind = %job["kind"].as_str().unwrap_or(""),
            outcome = %result["outcome"].as_str().unwrap_or(""),
            "introspection job finished"
        );
        self.backend.complete(&id, &result).await?;
        Ok(true)
    }

    /// Remove the guests and guest networks earlier runs of this worker left
    /// behind. Run at startup and, while idle, every [`REAP_EVERY`]: jobs
    /// run one at a time, so no guest of this worker is live then. The
    /// number of guests removed.
    pub async fn reap(&self) -> usize {
        let Some(runner) = &self.runner else {
            return 0;
        };
        match crate::sandbox::reap_leftovers(runner.as_ref()).await {
            Ok(0) => 0,
            Ok(n) => {
                tracing::warn!(removed = n, "removed leftover sandbox guests");
                n
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not check for leftover sandbox guests");
                0
            }
        }
    }

    pub async fn run_forever(&self, poll: Duration) {
        let mut last_reap = std::time::Instant::now();
        loop {
            match self.once().await {
                Ok(true) => continue,
                Ok(false) => {
                    if last_reap.elapsed() >= REAP_EVERY {
                        self.reap().await;
                        last_reap = std::time::Instant::now();
                    }
                }
                Err(e) => tracing::warn!(error = %e, "introspection worker"),
            }
            tokio::time::sleep(poll).await;
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn worker(base: &str, runner: Option<Box<dyn SandboxRunner>>) -> Worker {
        Worker {
            backend: Backend::direct(base, "tok"),
            worker_id: "w1".into(),
            runner,
            images: Images::default(),
            http: crate::http::guarded_client(),
        }
    }

    #[tokio::test]
    async fn claim_run_complete_cycle() {
        let ak = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/mcp/introspection/jobs/claim"))
            .and(header("authorization", "Bearer tok"))
            .and(body_partial_json(
                json!({"kinds": ["remote_probe"], "workerId": "w1"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jobId": "j1", "claimToken": "ct", "kind": "remote_probe",
                // A private target: the guard refuses it before any connection.
                "target": {"type": "remote", "url": "http://10.1.2.3/mcp"},
            })))
            .up_to_n_times(1)
            .mount(&ak)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/mcp/introspection/jobs/j1/complete"))
            .and(body_partial_json(
                json!({"claimToken": "ct", "outcome": "refused"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "stored"})))
            .expect(1)
            .mount(&ak)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/mcp/introspection/jobs/claim"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&ak)
            .await;
        let w = worker(&ak.uri(), None);
        assert_eq!(w.kinds(), vec!["remote_probe"]);
        assert_eq!(w.once().await, Ok(true));
        assert_eq!(w.once().await, Ok(false));
    }

    #[tokio::test]
    async fn job_kinds_without_runner_and_errors() {
        let w = worker("http://127.0.0.1:9", None);
        let r = w
            .run_job(&json!({"kind": "sandbox_run", "claimToken": "x", "target": {}}))
            .await;
        assert_eq!(r["outcome"], "unsupported");
        assert_eq!(r["claimToken"], "x");
        assert!(r["workerVersion"]
            .as_str()
            .unwrap()
            .starts_with("ak-mcp-introspector/"));
        let r = w.run_job(&json!({"kind": "nope"})).await;
        assert_eq!(r["outcome"], "unsupported");
        let r = w
            .run_job(&json!({"kind": "remote_probe", "target": {}}))
            .await;
        assert_eq!(r["outcome"], "error");
        assert!(w.once().await.is_err(), "unreachable backend is an error");
        // A sandbox job whose package is not from AK never starts.
        let w = worker(
            "http://127.0.0.1:9",
            Some(Box::new(crate::sandbox::OciRunner::default())),
        );
        assert_eq!(w.kinds(), vec!["remote_probe", "sandbox_run"]);
        let r = w
            .run_job(
                &json!({"kind": "sandbox_run", "jobId": "j", "akBaseUrl": "https://ak.test",
                "target": {"package": {"registryType": "npm", "identifier": "x", "version": "1.0.0",
                "registryBaseUrl": "https://registry.npmjs.org"}}}),
            )
            .await;
        assert_eq!(r["outcome"], "unsupported");
        // A sandbox job through an external runner that cannot start.
        let w = worker(
            "http://127.0.0.1:9",
            Some(Box::new(crate::sandbox::ExternalRunner {
                command: "/nonexistent/runner".into(),
            })),
        );
        let r = w
            .run_job(
                &json!({"kind": "sandbox_run", "jobId": "j", "akBaseUrl": "https://ak.test",
                "target": {"package": {"registryType": "npm", "identifier": "x", "version": "1.0.0",
                "registryBaseUrl": "https://ak.test/npm/r"}}}),
            )
            .await;
        assert_eq!(r["outcome"], "start_failed");
        assert_eq!(r["details"]["runner"], "external");
    }

    /// #5447: a job the deployment cannot isolate (here an AK base URL that
    /// is an IP address, which the forwarder cannot stand in for) is
    /// `start_failed`, which the backend retries, not a terminal
    /// `unsupported` stored as the server's state.
    #[tokio::test]
    async fn deployment_refusals_are_retryable() {
        let w = worker(
            "http://127.0.0.1:9",
            Some(Box::new(crate::sandbox::OciRunner::default())),
        );
        let r = w
            .run_job(
                &json!({"kind": "sandbox_run", "jobId": "j", "akBaseUrl": "https://203.0.113.10",
                "target": {"package": {"registryType": "npm", "identifier": "x", "version": "1.0.0",
                "registryBaseUrl": "https://203.0.113.10/npm/r"}}}),
            )
            .await;
        assert_eq!(r["outcome"], "start_failed", "{r}");
        assert!(r["error"].as_str().unwrap().contains("IP address"), "{r}");
    }

    /// The periodic reap: nothing without a runner; with one, this worker's
    /// leftover guests (by its owner label) are removed.
    #[tokio::test]
    async fn reap_removes_this_workers_leftovers() {
        assert_eq!(worker("http://127.0.0.1:9", None).reap().await, 0);
        let dir = std::env::temp_dir().join(format!("ak-reap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("engine");
        std::fs::write(
            &engine,
            "#!/bin/sh\ncase \"$1 $2\" in ps*) echo c1;; 'network ls') echo n1;; 'network rm') exit 1;; esac\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
        let runner = crate::sandbox::OciRunner {
            engine: engine.to_string_lossy().into_owned(),
            ..Default::default()
        };
        // A teardown command that fails is a warning, not an error.
        assert_eq!(
            worker("http://127.0.0.1:9", Some(Box::new(runner)))
                .reap()
                .await,
            1
        );
        let broken = crate::sandbox::OciRunner {
            engine: "/nonexistent/podman".into(),
            ..Default::default()
        };
        assert_eq!(
            worker("http://127.0.0.1:9", Some(Box::new(broken)))
                .reap()
                .await,
            0
        );
    }

    #[tokio::test]
    async fn push_and_refusals() {
        let ak = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/mcp/r/v0.1/servers/com.acme%2Fx/versions/1.0.0/capabilities",
            ))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({"snapshot": {"id": "s"}})),
            )
            .mount(&ak)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/mcp/introspection/jobs/claim"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(json!({"error": "mcp_forbidden"})),
            )
            .mount(&ak)
            .await;
        let b = Backend::direct(&format!("{}/", ak.uri()), "tok");
        assert_eq!(
            b.push("r", "com.acme/x", "1.0.0", &json!({}))
                .await
                .unwrap()["snapshot"]["id"],
            "s"
        );
        assert!(b
            .push("r", "com.acme/y", "1.0.0", &json!({}))
            .await
            .is_err());
        assert!(b
            .claim(&["remote_probe"], "w")
            .await
            .unwrap_err()
            .contains("403"));
        assert!(b.complete("j", &json!({})).await.is_err());
        let r = probe_remote(crate::http::guarded_client(), "http://169.254.169.254/").await;
        assert_eq!(r.outcome, "refused");
    }

    /// A result the backend would refuse is refused here with the reason
    /// (the backend would answer 400/413 and the job would hang until its
    /// lease expired).
    #[test]
    fn results_over_the_backend_limits_are_refused() {
        let ok = |tools: Vec<Value>, instructions: Option<String>| ProbeReport {
            outcome: "ok".into(),
            auth_state: "none".into(),
            tools,
            instructions,
            ..Default::default()
        };
        let fine = within_backend_limits(ok(vec![json!({"name": "t"})], Some("use it".into())));
        assert_eq!(fine.outcome, "ok");
        let long_name = within_backend_limits(ok(
            vec![json!({"name": "n".repeat(caps::MAX_NAME_LEN + 1)})],
            None,
        ));
        assert_eq!(long_name.outcome, "refused");
        assert!(long_name.error.unwrap().contains("backend's limits"));
        let long_instructions =
            within_backend_limits(ok(vec![], Some("x".repeat(caps::MAX_INSTRUCTIONS_LEN + 1))));
        assert_eq!(long_instructions.outcome, "refused");
        assert!(long_instructions.error.unwrap().contains("instructions"));
        let failed_stays = within_backend_limits(failed("timeout", "t"));
        assert_eq!(failed_stays.outcome, "timeout");

        // Within every per-item limit, over the request body limit.
        let big: Vec<Value> = (0..900)
            .map(|i| json!({"name": format!("t{i}"), "description": "d".repeat(2000)}))
            .collect();
        let mut body = within_backend_limits(ok(big, None)).to_result_json();
        assert_eq!(body["outcome"], "ok");
        body["claimToken"] = json!("ct");
        let body = within_body_limit(body);
        assert_eq!(body["outcome"], "refused");
        assert_eq!(body["claimToken"], "ct");
        assert!(body["error"].as_str().unwrap().contains("byte limit"));
        assert!(serde_json::to_vec(&body).unwrap().len() < MAX_BYTES);
    }
}
