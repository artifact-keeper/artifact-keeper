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
//! - `AK_IMAGE_BUILD_ADMIN_ONLY`     — `true` (the default) restricts building to administrators; `false` lets any user with write access on the repository build into it
//! - `AK_IMAGE_BUILD_PIP_INDEX_URL`  — a PyPI index every generated `pip install` uses (this instance's PyPI proxy, so package egress never leaves the registry); unset = pip's default

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

/// A package manager a spec may install with. The system managers run as
/// root in the final stage and need the spec to name the `user` the image
/// runs as afterwards; `pip` moves to a builder stage when `multistage` is
/// set; `conda` always installs in the final stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Apt,
    Dnf,
    Microdnf,
    Yum,
    Apk,
    #[default]
    Pip,
    Conda,
}

impl PackageManager {
    pub const ALL: [PackageManager; 7] = [
        PackageManager::Apt,
        PackageManager::Dnf,
        PackageManager::Microdnf,
        PackageManager::Yum,
        PackageManager::Apk,
        PackageManager::Pip,
        PackageManager::Conda,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt",
            PackageManager::Dnf => "dnf",
            PackageManager::Microdnf => "microdnf",
            PackageManager::Yum => "yum",
            PackageManager::Apk => "apk",
            PackageManager::Pip => "pip",
            PackageManager::Conda => "conda",
        }
    }

    /// Distribution package managers: root, final stage, cleanup after.
    pub fn is_system(self) -> bool {
        matches!(
            self,
            PackageManager::Apt
                | PackageManager::Dnf
                | PackageManager::Microdnf
                | PackageManager::Yum
                | PackageManager::Apk
        )
    }
}

/// One install step: which manager, which packages, and for conda which
/// channels. Groups render in the order given.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PackageGroup {
    pub manager: PackageManager,
    #[serde(default)]
    pub packages: Vec<String>,
    /// conda channels (`conda-forge`, `bioconda`); conda groups only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<String>,
}

/// What a user asks for. Either a structured spec (`base_image` plus
/// package groups, env, labels, user, workdir) or, when the instance allows
/// it, a whole `dockerfile` the server only checks and stamps.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ImageBuildSpec {
    /// The image to build on (`rayproject/ray:2.56.0`); must match the
    /// administrator's base allowlist when one is configured. Ignored when
    /// `dockerfile` is set (its FROM lines are checked instead).
    #[serde(default)]
    pub base_image: String,
    /// Install steps, rendered in order.
    #[serde(default)]
    pub packages: Vec<PackageGroup>,
    /// Build pip groups in a separate stage and copy only the installed
    /// packages into the final image, so build tooling and caches never ship.
    #[serde(default)]
    pub multistage: bool,
    /// A complete Dockerfile replacing the structured fields; accepted only
    /// when `AK_IMAGE_BUILD_ALLOW_DOCKERFILE=true`. Every FROM must match the
    /// base allowlist; the spec label is appended so inspection still knows
    /// what the image came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    /// Environment variables baked into the image.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// OCI labels baked into the image.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The user the image runs as (`ray`, `1000`, `1000:100`). Required
    /// when any system package group is present (they install as root).
    #[serde(default)]
    pub user: Option<String>,
    /// Working directory the image starts in.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Raw `RUN` lines. Refused unless `AK_IMAGE_BUILD_ALLOW_RUN=true`.
    #[serde(default)]
    pub run: Vec<String>,
    // --- Legacy shorthand fields, still accepted (and folded into groups by
    // `groups()` in the order apt, conda, pip) so specs recorded before
    // package groups render byte-for-byte the same.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apt: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conda: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conda_channels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pip: Vec<String>,
}

impl ImageBuildSpec {
    /// Whether this spec is a whole-Dockerfile override.
    pub fn is_dockerfile_override(&self) -> bool {
        self.dockerfile
            .as_deref()
            .map(|d| !d.trim().is_empty())
            .unwrap_or(false)
    }

    /// The install steps, legacy shorthand fields folded in first (apt,
    /// conda, pip — the order the legacy renderer used).
    pub fn groups(&self) -> Vec<PackageGroup> {
        let mut out = Vec::with_capacity(self.packages.len() + 3);
        if !self.apt.is_empty() {
            out.push(PackageGroup {
                manager: PackageManager::Apt,
                packages: self.apt.clone(),
                channels: vec![],
            });
        }
        if !self.conda.is_empty() {
            out.push(PackageGroup {
                manager: PackageManager::Conda,
                packages: self.conda.clone(),
                channels: self.conda_channels.clone(),
            });
        }
        if !self.pip.is_empty() {
            out.push(PackageGroup {
                manager: PackageManager::Pip,
                packages: self.pip.clone(),
                channels: vec![],
            });
        }
        out.extend(self.packages.iter().cloned());
        out
    }

    fn has_system_group(&self) -> bool {
        self.groups().iter().any(|g| g.manager.is_system())
    }
}

#[derive(Debug, Clone)]
pub struct ImageBuildSettings {
    pub buildkit_addr: Option<String>,
    pub buildctl_path: String,
    pub push_registry: Option<String>,
    pub registry_insecure: bool,
    pub base_allowlist: Vec<String>,
    pub allow_run: bool,
    /// Accept whole-Dockerfile specs (default false).
    pub allow_dockerfile: bool,
    pub timeout: Duration,
    pub max_concurrent: usize,
    /// Only administrators may build (default true).
    pub admin_only: bool,
    /// Index URL rendered into every `pip install`; None = pip's default.
    pub pip_index_url: Option<String>,
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
            allow_dockerfile: truthy(var("AK_IMAGE_BUILD_ALLOW_DOCKERFILE"), false),
            timeout: Duration::from_secs(
                var("AK_IMAGE_BUILD_TIMEOUT_SECS")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1800),
            ),
            max_concurrent: var("AK_IMAGE_BUILD_MAX_CONCURRENT")
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(2),
            admin_only: truthy(var("AK_IMAGE_BUILD_ADMIN_ONLY"), true),
            pip_index_url: var("AK_IMAGE_BUILD_PIP_INDEX_URL"),
        }
    }

    pub fn enabled(&self) -> bool {
        self.buildkit_addr.is_some() && self.push_registry.is_some()
    }

    /// Whether this caller may build on this instance.
    pub fn caller_may_build(&self, is_admin: bool) -> bool {
        !self.admin_only || is_admin
    }

    /// The managers a spec may use here, for the UI's dropdown.
    pub fn supported_managers(&self) -> Vec<&'static str> {
        PackageManager::ALL.iter().map(|m| m.as_str()).collect()
    }

    fn base_allowed(&self, image: &str) -> bool {
        self.base_allowlist.is_empty()
            || self
                .base_allowlist
                .iter()
                .any(|p| image.starts_with(p.as_str()))
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
static RPM_RE: OnceLock<Regex> = OnceLock::new();
static APK_RE: OnceLock<Regex> = OnceLock::new();
static CONDA_RE: OnceLock<Regex> = OnceLock::new();
static CHANNEL_RE: OnceLock<Regex> = OnceLock::new();
static ENV_KEY_RE: OnceLock<Regex> = OnceLock::new();
static LABEL_KEY_RE: OnceLock<Regex> = OnceLock::new();
static USER_RE: OnceLock<Regex> = OnceLock::new();
static NAME_RE: OnceLock<Regex> = OnceLock::new();
static TAG_RE: OnceLock<Regex> = OnceLock::new();
static FROM_RE: OnceLock<Regex> = OnceLock::new();

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
/// dnf / microdnf / yum: `name`, `name-1.2`, `name-1.2-3.el9`, `name.x86_64`.
fn rpm_re() -> &'static Regex {
    re(
        &RPM_RE,
        r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:-[0-9][A-Za-z0-9._:~+-]*)?$",
    )
}
fn apk_re() -> &'static Regex {
    re(
        &APK_RE,
        r"^[a-z0-9][a-z0-9._+-]*(?:[=~<>]{1,2}[A-Za-z0-9._+-]+)?$",
    )
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
/// `FROM [--platform=…] <image> [AS <alias>]`, case-insensitive, per line.
fn from_re() -> &'static Regex {
    re(
        &FROM_RE,
        r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
    )
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::Validation(msg.into())
}

/// Maximum Dockerfile override size.
const MAX_DOCKERFILE_BYTES: usize = 64 * 1024;

/// The base images a Dockerfile override builds on: every `FROM` that does
/// not name an earlier stage's alias (and is not `scratch`).
pub fn dockerfile_base_images(dockerfile: &str) -> Vec<String> {
    let mut aliases: Vec<String> = Vec::new();
    let mut bases = Vec::new();
    for cap in from_re().captures_iter(dockerfile) {
        let image = cap[1].to_string();
        let is_alias = aliases.iter().any(|a| a.eq_ignore_ascii_case(&image));
        if !is_alias && image != "scratch" {
            bases.push(image);
        }
        if let Some(alias) = cap.get(2) {
            aliases.push(alias.as_str().to_string());
        }
    }
    bases
}

fn validate_package(manager: PackageManager, p: &str) -> Result<()> {
    let ok = match manager {
        PackageManager::Apt => apt_re().is_match(p),
        PackageManager::Dnf | PackageManager::Microdnf | PackageManager::Yum => {
            rpm_re().is_match(p)
        }
        PackageManager::Apk => apk_re().is_match(p),
        PackageManager::Pip => pip_re().is_match(p.trim()),
        PackageManager::Conda => conda_re().is_match(p),
    };
    if ok {
        Ok(())
    } else {
        let noun = if manager == PackageManager::Pip {
            "requirement"
        } else {
            "package"
        };
        Err(invalid(format!(
            "{} {noun} {p:?} is not a valid {} {noun} spec",
            manager.as_str(),
            manager.as_str()
        )))
    }
}

/// Refuse anything the renderer could not turn into a safe Containerfile
/// line, and anything the administrator's policy forbids. Returns warnings
/// worth showing next to the rendered file.
pub fn validate_spec(spec: &ImageBuildSpec, settings: &ImageBuildSettings) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if spec.is_dockerfile_override() {
        if !settings.allow_dockerfile {
            return Err(invalid(
                "a Dockerfile override is not enabled on this instance (AK_IMAGE_BUILD_ALLOW_DOCKERFILE)",
            ));
        }
        let text = spec.dockerfile.as_deref().unwrap_or_default();
        if text.len() > MAX_DOCKERFILE_BYTES {
            return Err(invalid(format!(
                "dockerfile is larger than {MAX_DOCKERFILE_BYTES} bytes"
            )));
        }
        if text.contains('\0') {
            return Err(invalid("dockerfile must not contain NUL bytes"));
        }
        let bases = dockerfile_base_images(text);
        if bases.is_empty() {
            return Err(invalid("dockerfile has no FROM instruction"));
        }
        for base in &bases {
            let unpinned = base.trim_start_matches('$');
            if base.contains('$') {
                return Err(invalid(format!(
                    "FROM {base:?} uses a variable; name the base image literally so it can be checked"
                )));
            }
            if !image_ref_re().is_match(unpinned) {
                return Err(invalid(format!(
                    "FROM {base:?} is not a valid image reference"
                )));
            }
            if !settings.base_allowed(unpinned) {
                return Err(invalid(format!(
                    "FROM {base:?} is not under an allowed prefix ({})",
                    settings.base_allowlist.join(", ")
                )));
            }
        }
        if !spec.groups().is_empty() || !spec.env.is_empty() || !spec.run.is_empty() {
            warnings.push(
                "a Dockerfile override ignores the structured fields (packages, env, run)"
                    .to_string(),
            );
        }
        warnings.push(
            "a Dockerfile override is not reviewed by the builder; the scan gate is your check"
                .to_string(),
        );
        return Ok(warnings);
    }

    let base = spec.base_image.trim();
    if base.is_empty() {
        return Err(invalid("base_image is required"));
    }
    if !image_ref_re().is_match(base) {
        return Err(invalid(format!(
            "base_image {base:?} is not a valid image reference"
        )));
    }
    if !settings.base_allowed(base) {
        return Err(invalid(format!(
            "base_image {base:?} is not under an allowed prefix ({})",
            settings.base_allowlist.join(", ")
        )));
    }
    if !base.contains(':') && !base.contains('@') {
        warnings.push("base_image has no tag: `latest` is implied and moves under you".to_string());
    }
    let groups = spec.groups();
    for (i, g) in groups.iter().enumerate() {
        if g.packages.is_empty() {
            return Err(invalid(format!(
                "package group {} ({}) lists no packages",
                i + 1,
                g.manager.as_str()
            )));
        }
        for p in &g.packages {
            validate_package(g.manager, p)?;
            if g.manager == PackageManager::Pip && !p.contains("==") && !p.contains("===") {
                warnings.push(format!(
                    "pip requirement {p:?} is not pinned to an exact version"
                ));
            }
        }
        if !g.channels.is_empty() && g.manager != PackageManager::Conda {
            return Err(invalid(format!(
                "channels are only meaningful for conda (group {})",
                i + 1
            )));
        }
        for c in &g.channels {
            if !channel_re().is_match(c) {
                return Err(invalid(format!(
                    "conda channel {c:?} is not a valid channel name"
                )));
            }
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
    if spec.has_system_group() && spec.user.is_none() {
        return Err(invalid(
            "system packages install as root; set `user` to the account the image should run as afterwards",
        ));
    }
    if spec.multistage && !groups.iter().any(|g| g.manager == PackageManager::Pip) {
        warnings.push("multistage has no effect without a pip group".to_string());
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

/// Where the builder stage installs pip packages in a multistage build, and
/// what the final image imports them from.
pub const PIP_STAGE_TARGET: &str = "/opt/ak/site-packages";

fn push_packages(out: &mut String, packages: &[String]) {
    for p in packages {
        out.push_str(" \\\n        ");
        out.push_str(&sq(p.trim()));
    }
}

/// The `RUN` line for one package group. `pip_target` is Some in the
/// builder stage of a multistage build.
fn render_group(
    out: &mut String,
    g: &PackageGroup,
    pip_index_url: Option<&str>,
    pip_target: Option<&str>,
) {
    match g.manager {
        PackageManager::Apt => {
            out.push_str(
                "RUN apt-get update \\\n    && apt-get install -y --no-install-recommends",
            );
            push_packages(out, &g.packages);
            out.push_str(" \\\n    && rm -rf /var/lib/apt/lists/*\n");
        }
        PackageManager::Dnf => {
            out.push_str("RUN dnf install -y --setopt=install_weak_deps=False");
            push_packages(out, &g.packages);
            out.push_str(" \\\n    && dnf clean all\n");
        }
        PackageManager::Microdnf => {
            out.push_str("RUN microdnf install -y --setopt=install_weak_deps=0");
            push_packages(out, &g.packages);
            out.push_str(" \\\n    && microdnf clean all\n");
        }
        PackageManager::Yum => {
            out.push_str("RUN yum install -y");
            push_packages(out, &g.packages);
            out.push_str(" \\\n    && yum clean all\n");
        }
        PackageManager::Apk => {
            out.push_str("RUN apk add --no-cache");
            push_packages(out, &g.packages);
            out.push('\n');
        }
        PackageManager::Conda => {
            out.push_str("RUN conda install -y");
            for c in &g.channels {
                out.push_str(&format!(" -c {}", sq(c)));
            }
            push_packages(out, &g.packages);
            out.push_str(" \\\n    && conda clean -afy\n");
        }
        PackageManager::Pip => {
            out.push_str("RUN pip install --no-cache-dir");
            if let Some(index) = pip_index_url.map(str::trim).filter(|u| !u.is_empty()) {
                out.push_str(&format!(" --index-url {}", sq(index)));
            }
            if let Some(target) = pip_target {
                out.push_str(&format!(" --target {}", target));
            }
            push_packages(out, &g.packages);
            out.push('\n');
        }
    }
}

/// Render the Containerfile for a validated spec. Deterministic: the same
/// spec (and instance settings) always yields the same bytes, so the
/// preview a user approved is exactly what gets built.
pub fn render_containerfile(spec: &ImageBuildSpec) -> String {
    render_containerfile_with(spec, None)
}

/// `render_containerfile` with the instance's pip index: when set, every
/// `pip install` is pinned to it so package egress goes through the
/// registry's own PyPI proxy rather than the public index.
pub fn render_containerfile_with(spec: &ImageBuildSpec, pip_index_url: Option<&str>) -> String {
    let spec_json = serde_json::to_string(spec).unwrap_or_default();
    let spec_label = format!("LABEL {}={}\n", dq(SPEC_LABEL), dq(&spec_json));

    if let Some(text) = spec.dockerfile.as_deref().filter(|d| !d.trim().is_empty()) {
        // The user's file, verbatim, plus the stamp that says what it was
        // built from. A trailing LABEL applies to the final stage.
        let mut out = String::from(text.trim_end());
        out.push('\n');
        out.push_str(&spec_label);
        return out;
    }

    let base = spec.base_image.trim();
    let groups = spec.groups();
    let has_pip = groups.iter().any(|g| g.manager == PackageManager::Pip);
    let multistage = spec.multistage && has_pip;

    let mut out = String::new();
    out.push_str("# syntax=docker/dockerfile:1\n");
    out.push_str("# Generated by Artifact Keeper's image builder from a structured spec.\n");
    out.push_str("# Do not edit: change the spec and rebuild.\n");
    if multistage {
        // The builder stage is discarded, so it always runs as root: bases
        // that run as a non-root user (rayproject/ray runs as `ray`) cannot
        // create the stage target otherwise, and the final stage copies the
        // result in as root before switching to the spec's user.
        out.push_str(&format!("FROM {} AS builder\nUSER root\n", base));
        // System groups run here too: a base without pip (ubi-minimal plus a
        // `python3-pip` group, say) needs them before the pip installs, and
        // the stage is discarded so the duplication costs nothing in the
        // final image.
        for g in groups.iter().filter(|g| g.manager.is_system()) {
            render_group(&mut out, g, pip_index_url, None);
        }
        for g in groups.iter().filter(|g| g.manager == PackageManager::Pip) {
            render_group(&mut out, g, pip_index_url, Some(PIP_STAGE_TARGET));
        }
        out.push('\n');
    }
    out.push_str(&format!("FROM {}\n", base));
    let mut switched_to_root = false;
    for g in &groups {
        if g.manager == PackageManager::Pip && multistage {
            continue;
        }
        if g.manager.is_system() && !switched_to_root {
            out.push_str("USER root\n");
            switched_to_root = true;
        }
        render_group(&mut out, g, pip_index_url, None);
    }
    if multistage {
        out.push_str(&format!("COPY --from=builder {0} {0}\n", PIP_STAGE_TARGET));
        out.push_str(&format!(
            "ENV PYTHONPATH={0}${{PYTHONPATH:+:$PYTHONPATH}}\n",
            PIP_STAGE_TARGET
        ));
        out.push_str(&format!("ENV PATH={0}/bin:$PATH\n", PIP_STAGE_TARGET));
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
    out.push_str(&spec_label);
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

/// Spawn `cmd` and stream its stdout and stderr, line by line, to `sink`
/// in batches of roughly one second so a reader can follow along; stop and
/// kill it at `timeout`. Returns the exit status; a spawn failure, the
/// timeout and a wait failure are errors with the message the build row
/// records.
pub(crate) async fn stream_child<F, Fut>(
    cmd: &mut tokio::process::Command,
    timeout: Duration,
    mut sink: F,
) -> Result<std::process::ExitStatus>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| AppError::ServiceUnavailable(format!("could not start {program}: {e}")))?;

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

    let deadline = tokio::time::Instant::now() + timeout;
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
                    sink(std::mem::take(&mut pending)).await?;
                }
            }
            res = child.wait() => {
                break res;
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = child.start_kill();
                // Keep whatever the process said before it was stopped.
                if !pending.is_empty() {
                    let _ = sink(std::mem::take(&mut pending)).await;
                }
                return Err(AppError::Internal(format!(
                    "build exceeded {} seconds and was stopped",
                    timeout.as_secs()
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
        sink(pending).await?;
    }
    status.map_err(|e| AppError::Internal(format!("waiting for {program}: {e}")))
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
            let msg = failure_message(&e);
            let _ = store
                .append_log(id, &format!("\n== build failed: {msg} ==\n"))
                .await;
            let _ = store.finish(id, STATUS_FAILED, None, Some(&msg)).await;
        }
    }
}

/// The message a failed build records: the error's own text, without the
/// `Internal error:` / `Service unavailable:` prefix `AppError`'s `Display`
/// adds for HTTP responses, since this one is read from the build row.
fn failure_message(e: &AppError) -> String {
    match e {
        AppError::Internal(m) | AppError::ServiceUnavailable(m) => m.clone(),
        other => other.to_string(),
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

    let mut cmd = tokio::process::Command::new(&settings.buildctl_path);
    cmd.args(&args).env("DOCKER_CONFIG", &config_dir).env(
        "BUILDKIT_HOST",
        settings.buildkit_addr.as_deref().unwrap_or_default(),
    );
    let build_id = job.record.id;
    let status = stream_child(&mut cmd, settings.timeout, |chunk| async move {
        store.append_log(build_id, &chunk).await
    })
    .await;
    revoke().await;
    let status = status?;
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
            allow_dockerfile: false,
            timeout: Duration::from_secs(60),
            max_concurrent: 1,
            admin_only: true,
            pip_index_url: None,
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
            ..Default::default()
        }
    }

    fn group(manager: PackageManager, pkgs: &[&str]) -> PackageGroup {
        PackageGroup {
            manager,
            packages: pkgs.iter().map(|p| p.to_string()).collect(),
            channels: vec![],
        }
    }

    #[test]
    fn legacy_fields_fold_into_groups_in_the_old_order() {
        let mut s = spec();
        s.packages = vec![group(PackageManager::Apk, &["curl"])];
        let managers: Vec<_> = s.groups().iter().map(|g| g.manager).collect();
        assert_eq!(
            managers,
            vec![
                PackageManager::Apt,
                PackageManager::Conda,
                PackageManager::Pip,
                PackageManager::Apk
            ]
        );
        assert_eq!(s.groups()[1].channels, vec!["bioconda", "conda-forge"]);
        assert!(s.has_system_group());
        // JSON without the legacy fields and without `packages` is an empty spec.
        let bare: ImageBuildSpec = serde_json::from_str(r#"{"base_image":"python:3.12"}"#).unwrap();
        assert!(bare.groups().is_empty());
        assert!(!bare.multistage);
        assert!(!bare.is_dockerfile_override());
    }

    #[test]
    fn every_system_manager_renders_root_install_and_cleanup() {
        for (m, install, cleanup) in [
            (
                PackageManager::Apt,
                "apt-get install -y --no-install-recommends",
                "rm -rf /var/lib/apt/lists/*",
            ),
            (PackageManager::Dnf, "dnf install -y", "dnf clean all"),
            (
                PackageManager::Microdnf,
                "microdnf install -y",
                "microdnf clean all",
            ),
            (PackageManager::Yum, "yum install -y", "yum clean all"),
            (PackageManager::Apk, "apk add --no-cache", ""),
        ] {
            let s = ImageBuildSpec {
                base_image: "python:3.12".into(),
                packages: vec![group(m, &["git"])],
                user: Some("app".into()),
                ..Default::default()
            };
            let out = render_containerfile(&s);
            assert!(out.contains("USER root\nRUN "), "{m:?}: {out}");
            assert!(out.contains(install), "{m:?}: {out}");
            assert!(out.contains("'git'"), "{m:?}");
            assert!(out.contains(cleanup), "{m:?}: {out}");
            assert!(
                out.ends_with(
                    "USER app
"
                ),
                "{m:?}"
            );
            assert!(m.is_system());
            let st = settings();
            let mut permissive = st.clone();
            permissive.base_allowlist.clear();
            assert!(validate_spec(&s, &permissive).is_ok(), "{m:?}");
            let mut bad = s.clone();
            bad.packages[0].packages = vec!["git; rm -rf /".into()];
            assert!(validate_spec(&bad, &permissive).is_err(), "{m:?}");
        }
        assert!(!PackageManager::Pip.is_system() && !PackageManager::Conda.is_system());
        assert_eq!(PackageManager::ALL.len(), 7);
    }

    #[test]
    fn multistage_builds_pip_in_a_root_stage_and_copies_only_the_target() {
        let s = ImageBuildSpec {
            base_image: "registry.access.redhat.com/ubi9/ubi-minimal:9.4".into(),
            packages: vec![
                group(PackageManager::Microdnf, &["python3-pip"]),
                group(PackageManager::Pip, &["polars-lts-cpu==1.9.0"]),
            ],
            multistage: true,
            user: Some("1001".into()),
            ..Default::default()
        };
        let out = render_containerfile(&s);
        let (builder, final_stage) = out
            .split_once(
                "

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4
",
            )
            .expect("two stages");
        // Builder: root, the system group first (pip may not exist otherwise),
        // then pip into the fixed target.
        assert!(builder.contains(
            "FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4 AS builder
USER root
"
        ));
        assert!(builder.contains("RUN microdnf install -y"));
        assert!(builder.contains(&format!(
            "pip install --no-cache-dir --target {PIP_STAGE_TARGET}"
        )));
        // Final: the system group again, no pip, the copy and the path exports.
        assert!(final_stage.contains("RUN microdnf install -y"));
        assert!(!final_stage.contains("pip install"));
        assert!(final_stage.contains(&format!(
            "COPY --from=builder {PIP_STAGE_TARGET} {PIP_STAGE_TARGET}
"
        )));
        assert!(final_stage.contains(&format!(
            "ENV PYTHONPATH={PIP_STAGE_TARGET}${{PYTHONPATH:+:$PYTHONPATH}}
"
        )));
        assert!(final_stage.ends_with(
            "USER 1001
"
        ));
        assert_eq!(out.matches("AS builder").count(), 1);

        // Two-stage without a pip group has nothing to stage.
        let mut none = s.clone();
        none.packages.truncate(1);
        let mut st = settings();
        st.base_allowlist.clear();
        let w = validate_spec(&none, &st);
        assert!(w.is_err() || !render_containerfile(&none).contains("AS builder"));
    }

    #[test]
    fn dockerfile_override_is_gated_checked_and_stamped() {
        let st = settings();
        let df = "FROM rayproject/ray:2.56.0 AS build
RUN pip install x

FROM scratch
COPY --from=build /a /a
FROM rayproject/ray:2.56.0
";
        assert_eq!(
            dockerfile_base_images(df),
            vec![
                "rayproject/ray:2.56.0".to_string(),
                "rayproject/ray:2.56.0".to_string()
            ]
        );
        let s = ImageBuildSpec {
            dockerfile: Some(df.into()),
            ..Default::default()
        };
        assert!(s.is_dockerfile_override());
        let err = validate_spec(&s, &st).unwrap_err().to_string();
        assert!(
            err.contains("not enabled") || err.contains("Dockerfile"),
            "{err}"
        );

        let mut open = st.clone();
        open.allow_dockerfile = true;
        let warnings = validate_spec(&s, &open).unwrap();
        assert!(warnings.iter().any(|w| w.contains("not reviewed")));
        let out = render_containerfile(&s);
        assert!(out.starts_with(df));
        assert!(out.contains(&format!("LABEL \"{SPEC_LABEL}\"=")));

        let outside = ImageBuildSpec {
            dockerfile: Some(
                "FROM docker.io/library/nginx:1
"
                .into(),
            ),
            ..Default::default()
        };
        assert!(validate_spec(&outside, &open)
            .unwrap_err()
            .to_string()
            .contains("allowed prefix"));
        let empty = ImageBuildSpec {
            dockerfile: Some(
                "# nothing
"
                .into(),
            ),
            ..Default::default()
        };
        assert!(validate_spec(&empty, &open).is_err());
    }

    fn sh(script: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new("sh");
        c.arg("-c").arg(script);
        c
    }

    async fn collect(
        cmd: &mut tokio::process::Command,
        timeout: Duration,
    ) -> (Result<std::process::ExitStatus>, String) {
        let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let sink_log = log.clone();
        let status = stream_child(cmd, timeout, move |chunk| {
            let l = sink_log.clone();
            async move {
                l.lock().unwrap().push_str(&chunk);
                Ok(())
            }
        })
        .await;
        let out = log.lock().unwrap().clone();
        (status, out)
    }

    #[tokio::test]
    async fn stream_child_captures_both_streams_and_the_exit_status() {
        let (status, log) = collect(
            &mut sh("echo one; echo two >&2; sleep 1.2; echo three; exit 3"),
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(status.unwrap().code(), Some(3));
        for l in ["one\n", "two\n", "three\n"] {
            assert!(log.contains(l), "{log:?}");
        }
        let (status, log) = collect(&mut sh("exit 0"), Duration::from_secs(30)).await;
        assert!(status.unwrap().success());
        assert_eq!(log, "");
    }

    #[tokio::test]
    async fn stream_child_stops_a_hung_process_at_the_timeout() {
        let t0 = std::time::Instant::now();
        let (status, log) =
            collect(&mut sh("echo started; sleep 30"), Duration::from_secs(1)).await;
        assert!(t0.elapsed() < Duration::from_secs(10));
        assert_eq!(
            failure_message(&status.unwrap_err()),
            "build exceeded 1 seconds and was stopped"
        );
        assert!(log.contains("started"));
    }

    #[tokio::test]
    async fn stream_child_reports_an_unspawnable_program_and_a_failing_sink() {
        let mut missing = tokio::process::Command::new("/nonexistent/buildctl-for-tests");
        let (status, _) = collect(&mut missing, Duration::from_secs(5)).await;
        let msg = failure_message(&status.unwrap_err());
        assert!(
            msg.starts_with("could not start /nonexistent/buildctl-for-tests"),
            "{msg}"
        );

        let status = stream_child(
            &mut sh("echo x; sleep 1.5"),
            Duration::from_secs(10),
            |_| async { Err(AppError::Internal("sink broke".into())) },
        )
        .await;
        assert_eq!(failure_message(&status.unwrap_err()), "sink broke");
        assert_eq!(
            failure_message(&AppError::Validation("v".into())),
            "Validation error: v"
        );
    }

    #[test]
    fn settings_come_from_the_environment() {
        // Serialised with the other env-reading test through this lock.
        let _g = ENV_LOCK.lock().unwrap();
        let vars = [
            ("AK_BUILDKIT_ADDR", Some("tcp://bk:1234")),
            ("AK_IMAGE_BUILD_PUSH_REGISTRY", Some("http://reg.svc:8080/")),
            ("AK_IMAGE_BUILD_REGISTRY_INSECURE", None),
            (
                "AK_IMAGE_BUILD_BASE_ALLOWLIST",
                Some(" rayproject/ , ,python: "),
            ),
            ("AK_IMAGE_BUILD_ALLOW_RUN", Some("yes")),
            ("AK_IMAGE_BUILD_ALLOW_DOCKERFILE", Some("TRUE")),
            ("AK_IMAGE_BUILD_TIMEOUT_SECS", Some("90")),
            ("AK_IMAGE_BUILD_MAX_CONCURRENT", Some("0")),
            ("AK_IMAGE_BUILD_ADMIN_ONLY", Some("false")),
            ("AK_IMAGE_BUILD_PIP_INDEX_URL", Some("http://pypi/simple/")),
            ("AK_BUILDCTL_PATH", None),
        ];
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let s = ImageBuildSettings::from_env();
        assert!(s.enabled());
        assert_eq!(s.push_registry.as_deref(), Some("reg.svc:8080"));
        assert!(s.registry_insecure, "http:// implies insecure");
        assert_eq!(s.base_allowlist, vec!["rayproject/", "python:"]);
        assert!(s.allow_run && s.allow_dockerfile && !s.admin_only);
        assert_eq!(s.timeout, Duration::from_secs(90));
        assert_eq!(s.max_concurrent, 2, "0 falls back to the default");
        assert_eq!(s.buildctl_path, "buildctl");
        assert_eq!(s.pip_index_url.as_deref(), Some("http://pypi/simple/"));
        assert!(s.caller_may_build(false));
        assert_eq!(s.supported_managers().len(), 7);
        for (k, _) in vars {
            std::env::remove_var(k);
        }
        let off = ImageBuildSettings::from_env();
        assert!(!off.enabled() && off.admin_only && !off.caller_may_build(false));
        assert!(off.caller_may_build(true));
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        assert!(bad(|s| s.user = None).contains("system packages install as root"));
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
    fn pip_index_url_pins_every_pip_install() {
        let s = spec();
        let rendered = render_containerfile_with(
            &s,
            Some("https://artifacts.example/api/pypi/pypi-proxy/simple/"),
        );
        assert!(rendered.contains("RUN pip install --no-cache-dir --index-url 'https://artifacts.example/api/pypi/pypi-proxy/simple/'"));
        assert_eq!(
            render_containerfile_with(&s, Some("  ")),
            render_containerfile(&s)
        );
    }

    #[test]
    fn admin_only_gates_non_admins() {
        let mut s = settings();
        assert!(s.caller_may_build(true));
        assert!(!s.caller_may_build(false));
        s.admin_only = false;
        assert!(s.caller_may_build(false));
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
