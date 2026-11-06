//! Sandboxed stdio introspection (Phase 3): a pluggable [`SandboxRunner`].
//!
//! A sandbox job names one stdio package of a server version as AK serves
//! it (`registryBaseUrl` / OCI identifier rewritten to this AK instance).
//! [`guest_spec`] turns it into a runner-neutral [`GuestSpec`]: which image,
//! which command, which environment. The rules it applies:
//!
//! * install only from AK: `npx --registry=<registryBaseUrl>`, `uvx
//!   --default-index <registryBaseUrl>/simple`, or the AK-served OCI digest;
//!   publisher `runtimeArguments` are dropped (they are where `--registry`
//!   and `-v /:/host` would go), and environment variables that steer a
//!   package manager (`NPM_CONFIG_*`, `UV_*`, `PIP_*`, ...) are refused;
//! * no real secrets: every `isSecret` value, every required value without
//!   a default, and every `{template}` value becomes `AK_PLACEHOLDER_<NAME>`;
//! * the guest's network is the operator's AK-only network for installs,
//!   and `none` for an OCI image (already pulled by the engine);
//! * 120 s wall clock, enforced by the worker around the whole run; when
//!   the run ends the guest is removed through the engine (killing the
//!   engine client alone leaves the container running), and leftovers of a
//!   crashed worker are reaped at startup.
//!
//! Runners render a spec into a process whose stdin/stdout is the guest's:
//! [`OciRunner`] (docker/podman with gVisor `runsc` by default, Kata or any
//! other OCI runtime by configuration) and [`ExternalRunner`] (an operator
//! command, e.g. a Firecracker launcher, that receives the spec as JSON).

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

pub const WALL_CLOCK: Duration = Duration::from_secs(120);
pub const PLACEHOLDER_PREFIX: &str = "AK_PLACEHOLDER_";
/// The label every guest container carries (value: the job id).
pub const SANDBOX_LABEL: &str = "com.artifactkeeper.mcp-sandbox";
/// The label naming the worker that started a guest (value: the worker id);
/// startup reaping removes only this worker's leftovers.
pub const OWNER_LABEL: &str = "com.artifactkeeper.mcp-sandbox.owner";
/// How long the engine client or launcher gets after `SIGTERM`, and each
/// cleanup command in total, before it is killed.
pub const STOP_GRACE: Duration = Duration::from_secs(5);
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Engine exit codes that mean the engine (not the guest) failed: `125`
/// the engine itself (runtime or network missing, pull failed, name in
/// use), `126` the command could not be invoked, `127` not found. Docker and
/// Podman both use them; an external launcher should too.
pub const ENGINE_FAILURE_CODES: &[i32] = &[125, 126, 127];
/// Bytes of the engine's stderr kept for the error of a start failure.
const STDERR_KEEP: usize = 2048;

/// The worker's environment variables the engine client or external
/// launcher inherits; everything else (the `mcp:introspect` token above
/// all) is cleared. `AK_MCP_SANDBOX_*` (launcher configuration) and the
/// names in `AK_MCP_SANDBOX_PASS_ENV` (comma separated) pass too.
pub const ENGINE_ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "CONTAINERS_CONF",
    "CONTAINERS_STORAGE_CONF",
    "CONTAINERS_REGISTRIES_CONF",
    "REGISTRY_AUTH_FILE",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "KUBECONFIG",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];
/// Never passed to the engine, whatever `AK_MCP_SANDBOX_PASS_ENV` says.
pub const ENGINE_ENV_NEVER: &[&str] = &["AK_MCP_INTROSPECTOR_TOKEN", "AK_TOKEN"];

/// Environment the guest always gets (and the publisher may not override).
pub const BASE_ENV: &[(&str, &str)] = &[
    ("HOME", "/tmp/home"),
    ("XDG_CACHE_HOME", "/tmp/cache"),
    ("npm_config_cache", "/tmp/npm"),
    ("npm_config_update_notifier", "false"),
    ("UV_CACHE_DIR", "/tmp/uv"),
    ("UV_TOOL_DIR", "/tmp/uv-tools"),
    ("UV_NO_CONFIG", "1"),
    ("CI", "1"),
];

/// Prefixes of environment names that would re-route an install or a
/// runtime; a publisher's value for one is dropped.
pub const REFUSED_ENV_PREFIXES: &[&str] = &[
    "NPM_CONFIG",
    "YARN_",
    "PNPM_",
    "UV_",
    "PIP_",
    "PYTHON",
    "NODE_OPTIONS",
    "LD_",
    "DYLD_",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "PATH",
    "HOME",
    "XDG_",
    "CI",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    Unsupported(String),
    Invalid(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Unsupported(m) | SandboxError::Invalid(m) => {
                write!(f, "{m}")
            }
        }
    }
}

/// Runner images (the operator should mirror them through AK too). The
/// defaults are pinned by digest: a tag is mutable, and whoever can move it
/// chooses what every npm and PyPI guest runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Images {
    pub node: String,
    pub python: String,
}

pub const DEFAULT_NODE_IMAGE: &str = "docker.io/library/node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914";
pub const DEFAULT_PYTHON_IMAGE: &str =
    "ghcr.io/astral-sh/uv:python3.12-alpine@sha256:aef1a1327a732e74892765e22fa528499eca3f828140a66ed46b2f8df51bd0dc";

impl Default for Images {
    fn default() -> Self {
        Self {
            node: DEFAULT_NODE_IMAGE.into(),
            python: DEFAULT_PYTHON_IMAGE.into(),
        }
    }
}

impl Images {
    /// The configured runner images that are not pinned by digest.
    pub fn unpinned(&self) -> Vec<&str> {
        [self.node.as_str(), self.python.as_str()]
            .into_iter()
            .filter(|i| !i.contains("@sha256:"))
            .collect()
    }
}

/// What to run in the guest, independent of the isolation technology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestSpec {
    pub job_id: String,
    pub image: String,
    /// The guest command; empty = the image's entrypoint (OCI packages).
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// `ak-only` (installs from AK) or `none`.
    pub network: String,
    /// The AK origin the guest may reach.
    pub ak_base_url: String,
    pub wall_clock_ms: u64,
    pub notes: Vec<String>,
    /// The image is the job's own package (an OCI server), pulled for this
    /// job only: remove it after the run. Runner images are kept.
    pub prune_image: bool,
}

fn placeholder(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "{PLACEHOLDER_PREFIX}{}",
        if clean.is_empty() {
            "VALUE".into()
        } else {
            clean
        }
    )
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

/// The value an input (argument or environment variable) gets in the guest.
fn input_value(input: &Value, label: &str) -> Option<String> {
    let given = s(input, "value").or_else(|| s(input, "default"));
    if flag(input, "isSecret") || given.is_some_and(|g| g.contains('{')) {
        return Some(placeholder(label));
    }
    match given {
        Some(g) => Some(g.to_string()),
        None if flag(input, "isRequired") => Some(placeholder(label)),
        None => None,
    }
}

fn valid_env_name(n: &str) -> bool {
    let mut chars = n.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && n.len() <= 128
}

/// The guest environment: [`BASE_ENV`] plus the package's
/// `environmentVariables` (placeholders for secrets, refused names dropped).
pub fn guest_env(package: &Value, notes: &mut Vec<String>) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = BASE_ENV
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let vars = package
        .get("environmentVariables")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    for var in &vars {
        let Some(name) = s(var, "name") else { continue };
        let upper = name.to_ascii_uppercase();
        if !valid_env_name(name) || REFUSED_ENV_PREFIXES.iter().any(|p| upper.starts_with(p)) {
            notes.push(format!("environment variable `{name}` dropped"));
            continue;
        }
        if let Some(v) = input_value(var, name) {
            env.retain(|(k, _)| k != name);
            env.push((name.to_string(), v));
        }
    }
    env
}

/// The package's `packageArguments` for the guest command.
pub fn package_args(package: &Value) -> Vec<String> {
    let args = package
        .get("packageArguments")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let label = s(a, "valueHint")
            .or_else(|| s(a, "name"))
            .map(String::from)
            .unwrap_or_else(|| format!("ARG{i}"));
        match s(a, "type") {
            Some("named") => {
                let Some(name) = s(a, "name") else { continue };
                if let Some(v) = input_value(a, &label) {
                    out.push(name.to_string());
                    out.push(v);
                } else if flag(a, "isRequired") || a.get("value").is_none() {
                    out.push(name.to_string());
                }
            }
            _ => {
                if let Some(v) = input_value(a, &label) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The claimed job's `target` and AK origin as a runner-neutral spec.
pub fn guest_spec(
    job_id: &str,
    target: &Value,
    ak_base_url: &str,
    images: &Images,
) -> Result<GuestSpec, SandboxError> {
    let package = target
        .get("package")
        .ok_or_else(|| SandboxError::Invalid("job has no package".into()))?;
    let kind = s(package, "registryType").unwrap_or("");
    let identifier = s(package, "identifier")
        .filter(|i| !i.is_empty() && !i.starts_with('-'))
        .ok_or_else(|| SandboxError::Invalid("package has no identifier".into()))?;
    let mut notes = Vec::new();
    if package
        .get("runtimeArguments")
        .and_then(|a| a.as_array())
        .is_some_and(|a| !a.is_empty())
    {
        notes.push("runtimeArguments ignored".into());
    }
    let env = guest_env(package, &mut notes);
    let args = package_args(package);
    let ak = ak_base_url.trim_end_matches('/');
    let registry = || {
        s(package, "registryBaseUrl")
            .filter(|r| r.starts_with(ak))
            .map(|r| r.trim_end_matches('/').to_string())
            .ok_or_else(|| SandboxError::Invalid("registryBaseUrl is not this AK instance".into()))
    };
    let version = || {
        s(package, "version")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| SandboxError::Invalid("package has no pinned version".into()))
    };
    let (image, mut argv, network) = match kind {
        "npm" => (
            images.node.clone(),
            vec![
                "npx".to_string(),
                "--yes".into(),
                format!("--registry={}", registry()?),
                format!("{identifier}@{}", version()?),
            ],
            "ak-only",
        ),
        "pypi" => (
            images.python.clone(),
            vec![
                "uvx".to_string(),
                "--no-config".into(),
                "--default-index".into(),
                format!("{}/simple", registry()?),
                format!("{identifier}@{}", version()?),
            ],
            "ak-only",
        ),
        "oci" => {
            let host = artifact_keeper_backend::formats::mcp::host_of(ak);
            if !identifier.starts_with(&format!("{host}/")) || !identifier.contains("@sha256:") {
                return Err(SandboxError::Invalid(
                    "OCI identifier is not a digest served by this AK instance".into(),
                ));
            }
            (identifier.to_string(), Vec::new(), "none")
        }
        other => {
            return Err(SandboxError::Unsupported(format!(
                "registryType `{other}` is not run in the sandbox"
            )))
        }
    };
    argv.extend(args);
    let mut env = env;
    if kind == "npm" {
        env.push(("npm_config_registry".into(), registry()?));
    }
    Ok(GuestSpec {
        job_id: job_id.to_string(),
        image,
        argv,
        env,
        network: network.into(),
        ak_base_url: ak.to_string(),
        wall_clock_ms: WALL_CLOCK.as_millis() as u64,
        notes,
        prune_image: kind == "oci",
    })
}

/// One command: a program and its arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

impl Cmd {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }
}

/// A process to start: its stdin/stdout are the guest's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunPlan {
    pub program: String,
    pub args: Vec<String>,
    /// Run after the guest, whatever the outcome: remove the container
    /// (the engine client exiting does not stop it) and prune the job's
    /// own image.
    pub cleanup: Vec<Cmd>,
}

/// Leftover guests of this worker: `list` prints one container id per
/// line, `remove` (with the ids appended) removes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reap {
    pub list: Cmd,
    pub remove: Cmd,
}

/// The pluggable sandbox interface. A runner renders a [`GuestSpec`] into
/// the command that starts the throwaway guest; the worker spawns it, speaks
/// MCP over its stdio, stops it after the wall clock and runs the plan's
/// cleanup.
pub trait SandboxRunner: Send + Sync {
    fn name(&self) -> &str;
    fn plan(&self, spec: &GuestSpec) -> Result<RunPlan, SandboxError>;
    /// How to find and remove guests a previous run of this worker left
    /// behind (it crashed or was killed mid-job). `None`: the runner keeps
    /// no state between jobs.
    fn reap(&self) -> Option<Reap> {
        None
    }
}

/// Whether `runtime` (a name or a path) is a sandbox runtime: gVisor
/// (`runsc`, `io.containerd.runsc.v1`, ...) or Kata (`kata-fc`,
/// `kata-qemu`, `io.containerd.kata.v2`, ...). `runc`, `crun`, `youki`
/// and anything else are plain containers.
pub fn is_sandbox_runtime(runtime: &str) -> bool {
    let base = runtime.rsplit('/').next().unwrap_or(runtime);
    base.split('.')
        .any(|seg| seg.starts_with("runsc") || seg.starts_with("kata"))
}

/// `s` restricted to what a container name or label value may hold.
fn name_part(s: &str, max: usize) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .take(max)
        .collect();
    if out.is_empty() {
        "job".into()
    } else {
        out
    }
}

/// docker/podman with an OCI runtime (gVisor `runsc` by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRunner {
    /// `podman`, `docker`, or a path (`AK_MCP_SANDBOX_ENGINE`).
    pub engine: String,
    /// `runsc` (default), `kata-fc`, ...; empty = the engine's default
    /// (`AK_MCP_SANDBOX_RUNTIME`). Anything but gVisor or Kata is refused
    /// unless `allow_default_runtime`.
    pub runtime: String,
    /// The pre-created network that reaches only AK (`AK_MCP_SANDBOX_NETWORK`).
    pub ak_network: String,
    pub memory: String,
    pub cpus: String,
    pub pids_limit: u32,
    pub tmpfs_size: String,
    pub allow_default_runtime: bool,
    /// The worker id, as the [`OWNER_LABEL`] of every guest it starts.
    pub owner: String,
}

impl Default for OciRunner {
    fn default() -> Self {
        Self {
            engine: "podman".into(),
            runtime: "runsc".into(),
            ak_network: "ak-mcp-sandbox".into(),
            memory: "1g".into(),
            cpus: "1".into(),
            pids_limit: 256,
            tmpfs_size: "512m".into(),
            allow_default_runtime: false,
            owner: "ak-mcp-introspector".into(),
        }
    }
}

impl OciRunner {
    /// Podman takes flags Docker does not (`--timeout`, `--http-proxy`).
    fn is_podman(&self) -> bool {
        self.engine
            .rsplit('/')
            .next()
            .is_some_and(|b| b.starts_with("podman"))
    }

    fn owner_filter(&self) -> String {
        format!("label={OWNER_LABEL}={}", name_part(&self.owner, 128))
    }
}

impl SandboxRunner for OciRunner {
    fn name(&self) -> &str {
        "oci"
    }

    fn plan(&self, spec: &GuestSpec) -> Result<RunPlan, SandboxError> {
        if !self.allow_default_runtime && !is_sandbox_runtime(&self.runtime) {
            let what = if self.runtime.is_empty() {
                "no sandbox runtime configured (AK_MCP_SANDBOX_RUNTIME, e.g. runsc)".to_string()
            } else {
                format!(
                    "runtime `{}` is not a sandbox runtime (gVisor runsc or Kata)",
                    self.runtime
                )
            };
            return Err(SandboxError::Unsupported(format!(
                "{what}; a plain container is not an isolation boundary for \
                 attacker-chosen install scripts (AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME=true \
                 runs it anyway)"
            )));
        }
        let network = match spec.network.as_str() {
            "none" => "none".to_string(),
            _ => self.ak_network.clone(),
        };
        // A fresh name per attempt: a retry never collides with a guest of
        // an earlier attempt that is still being removed.
        let job = name_part(&spec.job_id, 64);
        let name = format!(
            "ak-mcp-sbx-{job}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "-i".into(),
            format!("--name={name}"),
            format!("--label={SANDBOX_LABEL}={job}"),
            format!("--label={OWNER_LABEL}={}", name_part(&self.owner, 128)),
        ];
        if !self.runtime.is_empty() {
            args.push(format!("--runtime={}", self.runtime));
        }
        args.extend([
            format!("--network={network}"),
            "--read-only".into(),
            format!("--tmpfs=/tmp:rw,exec,nosuid,nodev,size={}", self.tmpfs_size),
            "--user=65532:65532".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            format!("--pids-limit={}", self.pids_limit),
            format!("--memory={}", self.memory),
            format!("--cpus={}", self.cpus),
            "--pull=missing".into(),
            "--stop-timeout=1".into(),
            // stdout is read over the attach stream; a log driver would
            // only copy everything the guest prints to the host's disk.
            "--log-driver=none".into(),
            "--workdir=/tmp".into(),
        ]);
        if self.is_podman() {
            // conmon kills the guest itself, should the worker die before
            // its cleanup; and the worker's proxy variables stay out.
            args.push(format!("--timeout={}", spec.wall_clock_ms / 1000 + 10));
            args.push("--http-proxy=false".into());
        }
        for (k, v) in &spec.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        args.push(spec.image.clone());
        args.extend(spec.argv.iter().cloned());
        let mut cleanup = vec![Cmd::new(&self.engine, &["rm", "-f", &name])];
        if spec.prune_image {
            cleanup.push(Cmd::new(&self.engine, &["rmi", &spec.image]));
        }
        Ok(RunPlan {
            program: self.engine.clone(),
            args,
            cleanup,
        })
    }

    fn reap(&self) -> Option<Reap> {
        Some(Reap {
            list: Cmd::new(
                &self.engine,
                &["ps", "-a", "-q", "--filter", &self.owner_filter()],
            ),
            remove: Cmd::new(&self.engine, &["rm", "-f"]),
        })
    }
}

/// An operator-supplied launcher (microVM, Kubernetes job, ...): started as
/// `<command> <spec JSON>`; its stdin/stdout must be the guest's. When the
/// run ends it gets `SIGTERM` (then, after [`STOP_GRACE`], `SIGKILL`) and
/// must remove its guest; an exit code in [`ENGINE_FAILURE_CODES`] says the
/// launcher, not the guest, failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRunner {
    pub command: String,
}

impl SandboxRunner for ExternalRunner {
    fn name(&self) -> &str {
        "external"
    }

    fn plan(&self, spec: &GuestSpec) -> Result<RunPlan, SandboxError> {
        Ok(RunPlan {
            program: self.command.clone(),
            args: vec![
                serde_json::to_string(spec).map_err(|e| SandboxError::Invalid(e.to_string()))?
            ],
            cleanup: Vec::new(),
        })
    }
}

/// The runner the environment configures: `AK_MCP_SANDBOX_COMMAND` selects
/// an [`ExternalRunner`], otherwise an [`OciRunner`] from
/// `AK_MCP_SANDBOX_ENGINE` / `_RUNTIME` / `_NETWORK` / `_MEMORY` / `_CPUS`,
/// labelling its guests with `owner` (the worker id).
pub fn runner_from_env(
    get: impl Fn(&str) -> Option<String>,
    owner: &str,
) -> Box<dyn SandboxRunner> {
    if let Some(command) = get("AK_MCP_SANDBOX_COMMAND").filter(|c| !c.is_empty()) {
        return Box::new(ExternalRunner { command });
    }
    let d = OciRunner::default();
    Box::new(OciRunner {
        engine: get("AK_MCP_SANDBOX_ENGINE").unwrap_or(d.engine),
        runtime: get("AK_MCP_SANDBOX_RUNTIME").unwrap_or(d.runtime),
        ak_network: get("AK_MCP_SANDBOX_NETWORK").unwrap_or(d.ak_network),
        memory: get("AK_MCP_SANDBOX_MEMORY").unwrap_or(d.memory),
        cpus: get("AK_MCP_SANDBOX_CPUS").unwrap_or(d.cpus),
        allow_default_runtime: get("AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME").as_deref()
            == Some("true"),
        owner: owner.to_string(),
        ..d
    })
}

pub fn images_from_env(get: impl Fn(&str) -> Option<String>) -> Images {
    let d = Images::default();
    Images {
        node: get("AK_MCP_SANDBOX_NODE_IMAGE").unwrap_or(d.node),
        python: get("AK_MCP_SANDBOX_PYTHON_IMAGE").unwrap_or(d.python),
    }
}

/// The part of the worker's environment the engine client or launcher
/// gets: [`ENGINE_ENV_ALLOW`], `AK_MCP_SANDBOX_*` and the names listed in
/// `pass` (comma separated), never [`ENGINE_ENV_NEVER`].
pub fn engine_env(
    vars: impl IntoIterator<Item = (String, String)>,
    pass: Option<&str>,
) -> Vec<(String, String)> {
    let extra: Vec<&str> = pass
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    vars.into_iter()
        .filter(|(k, _)| {
            !ENGINE_ENV_NEVER.contains(&k.as_str())
                && (ENGINE_ENV_ALLOW.contains(&k.as_str())
                    || k.starts_with("AK_MCP_SANDBOX_")
                    || extra.contains(&k.as_str()))
        })
        .collect()
}

/// A command with the worker's environment cleared down to [`engine_env`].
fn command(program: &str, args: &[String]) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(program);
    c.args(args)
        .env_clear()
        .envs(engine_env(
            std::env::vars(),
            std::env::var("AK_MCP_SANDBOX_PASS_ENV").ok().as_deref(),
        ))
        .kill_on_drop(true);
    c
}

/// Run a short engine command (cleanup, listing) to completion within
/// `limit`; its stdout when it ran.
async fn run_cmd(cmd: &Cmd, limit: Duration) -> Option<(std::process::ExitStatus, String)> {
    let child = command(&cmd.program, &cmd.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let out = tokio::time::timeout(limit, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    Some((
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

/// Remove the guests a previous run of this worker left behind. The number
/// removed, or why that could not be checked.
pub async fn reap_leftovers(runner: &dyn SandboxRunner) -> Result<usize, String> {
    let Some(reap) = runner.reap() else {
        return Ok(0);
    };
    let (status, out) = run_cmd(&reap.list, CLEANUP_TIMEOUT)
        .await
        .ok_or_else(|| format!("`{}` could not be run", reap.list.program))?;
    if !status.success() {
        return Err(format!("listing leftover guests failed ({status})"));
    }
    let ids: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let mut remove = reap.remove.clone();
    remove.args.extend(ids.iter().cloned());
    match run_cmd(&remove, CLEANUP_TIMEOUT).await {
        Some((s, _)) if s.success() => Ok(ids.len()),
        _ => Err(format!("removing {} leftover guest(s) failed", ids.len())),
    }
}

/// Stop the engine client or launcher: `SIGTERM`, then `SIGKILL` after
/// [`STOP_GRACE`].
async fn stop(child: &mut tokio::process::Child) {
    #[cfg(target_os = "linux")]
    if let Some(pid) = child.id().and_then(|p| i32::try_from(p).ok()) {
        // SAFETY: kill(2) on the pid of our own, not yet reaped, child.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    if tokio::time::timeout(STOP_GRACE, child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

/// Run a plan and probe the guest over its stdio, bounded by the wall
/// clock. Whatever the outcome, the guest is stopped and the plan's cleanup
/// (removing the container) runs before this returns.
pub async fn run_and_probe(
    plan: &RunPlan,
    max_items: usize,
    max_bytes: usize,
) -> crate::protocol::ProbeReport {
    run_and_probe_within(plan, max_items, max_bytes, WALL_CLOCK).await
}

pub async fn run_and_probe_within(
    plan: &RunPlan,
    max_items: usize,
    max_bytes: usize,
    wall_clock: Duration,
) -> crate::protocol::ProbeReport {
    let report = probe_child(plan, max_items, max_bytes, wall_clock).await;
    for cmd in &plan.cleanup {
        if run_cmd(cmd, CLEANUP_TIMEOUT).await.is_none() {
            tracing::warn!(program = %cmd.program, args = ?cmd.args, "sandbox cleanup did not run");
        }
    }
    report
}

async fn probe_child(
    plan: &RunPlan,
    max_items: usize,
    max_bytes: usize,
    wall_clock: Duration,
) -> crate::protocol::ProbeReport {
    use crate::protocol::ProbeReport;
    use tokio::io::AsyncReadExt;
    let mut child = match command(&plan.program, &plan.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeReport {
                outcome: "start_failed".into(),
                auth_state: "none".into(),
                error: Some(format!("could not start the sandbox: {e}")),
                ..Default::default()
            }
        }
    };
    // The engine's (and the guest's) stderr: drained so neither blocks on
    // a full pipe, the first bytes kept for a start failure's error.
    let stderr = child.stderr.take().map(|mut e| {
        tokio::spawn(async move {
            let mut kept = Vec::new();
            let mut buf = [0u8; 8192];
            while let Ok(n) = e.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let room = STDERR_KEEP.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            String::from_utf8_lossy(&kept).trim().to_string()
        })
    });
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(&mut child).await;
        return ProbeReport {
            outcome: "start_failed".into(),
            auth_state: "none".into(),
            error: Some("sandbox stdio unavailable".into()),
            ..Default::default()
        };
    };
    // Installs on first run are slow: one message may take most of the
    // wall clock, the whole run may not exceed it.
    let mut t = crate::stdio::StdioTransport::new(stdout, stdin, wall_clock, max_bytes);
    let probed = tokio::time::timeout(wall_clock, crate::protocol::probe(&mut t, max_items)).await;
    drop(t);
    let report = match probed {
        Ok(mut r) => {
            if r.outcome == "start_failed" {
                // The guest's stdout closed before it answered. Either the
                // engine failed to start it (its exit code says so) or the
                // server would not start without configuration.
                let code = match tokio::time::timeout(STOP_GRACE, child.wait()).await {
                    Ok(Ok(status)) => status.code(),
                    _ => None,
                };
                if let Some(c) = code {
                    r.details.insert("exitCode".into(), serde_json::json!(c));
                }
                if code.is_some_and(|c| ENGINE_FAILURE_CODES.contains(&c)) {
                    let msg = match stderr {
                        Some(h) => tokio::time::timeout(Duration::from_secs(2), h)
                            .await
                            .ok()
                            .and_then(|r| r.ok())
                            .unwrap_or_default(),
                        None => String::new(),
                    };
                    r.error = Some(format!(
                        "the sandbox engine failed to start the guest (exit {}){}{}",
                        code.unwrap_or_default(),
                        if msg.is_empty() { "" } else { ": " },
                        msg
                    ));
                    stop(&mut child).await;
                    return r;
                }
                r.outcome = "needs_config".into();
            }
            r
        }
        Err(_) => ProbeReport {
            outcome: "timeout".into(),
            auth_state: "none".into(),
            error: Some(format!(
                "sandbox wall clock ({} s) exceeded",
                wall_clock.as_secs()
            )),
            ..Default::default()
        },
    };
    stop(&mut child).await;
    report
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AK: &str = "https://ak.example.test";

    fn npm_target() -> Value {
        json!({"type": "package", "index": 0, "registryType": "npm", "package": {
            "registryType": "npm", "identifier": "@acme/weather", "version": "1.2.3",
            "registryBaseUrl": "https://ak.example.test/npm/npm-virtual",
            "transport": {"type": "stdio"},
            "runtimeArguments": [{"type": "named", "name": "--registry", "value": "https://evil.test"}],
            "packageArguments": [
                {"type": "positional", "value": "serve"},
                {"type": "named", "name": "--token", "isSecret": true},
                {"type": "named", "name": "--verbose"},
                {"type": "named", "name": "--region", "default": "eu"},
                {"type": "positional", "valueHint": "workspace", "isRequired": true},
                {"type": "positional", "value": "{user_dir}"},
                {"type": "positional"},
            ],
            "environmentVariables": [
                {"name": "API_KEY", "isSecret": true, "isRequired": true},
                {"name": "LOG_LEVEL", "default": "debug"},
                {"name": "OPTIONAL"},
                {"name": "REQUIRED_NO_DEFAULT", "isRequired": true},
                {"name": "NPM_CONFIG_REGISTRY", "value": "https://evil.test"},
                {"name": "npm_config_registry", "value": "https://evil.test"},
                {"name": "HOME", "value": "/root"},
                {"name": "BAD NAME", "value": "x"},
            ],
        }})
    }

    #[test]
    fn npm_spec_installs_only_from_ak_with_placeholders() {
        let spec = guest_spec("j1", &npm_target(), AK, &Images::default()).unwrap();
        assert_eq!(spec.image, Images::default().node);
        assert_eq!(
            &spec.argv[..4],
            [
                "npx",
                "--yes",
                "--registry=https://ak.example.test/npm/npm-virtual",
                "@acme/weather@1.2.3"
            ]
        );
        assert_eq!(
            &spec.argv[4..],
            [
                "serve",
                "--token",
                "AK_PLACEHOLDER___TOKEN",
                "--verbose",
                "--region",
                "eu",
                "AK_PLACEHOLDER_WORKSPACE",
                "AK_PLACEHOLDER_ARG5"
            ]
        );
        assert!(
            !spec.argv.iter().any(|a| a.contains("evil")),
            "runtimeArguments never reach the guest"
        );
        let env: std::collections::HashMap<_, _> = spec.env.iter().cloned().collect();
        assert_eq!(env["API_KEY"], "AK_PLACEHOLDER_API_KEY");
        assert_eq!(env["LOG_LEVEL"], "debug");
        assert_eq!(
            env["REQUIRED_NO_DEFAULT"],
            "AK_PLACEHOLDER_REQUIRED_NO_DEFAULT"
        );
        assert!(!env.contains_key("OPTIONAL"));
        assert!(!env.contains_key("NPM_CONFIG_REGISTRY"));
        assert_eq!(
            env["npm_config_registry"],
            "https://ak.example.test/npm/npm-virtual"
        );
        assert_eq!(env["HOME"], "/tmp/home");
        assert_eq!(spec.network, "ak-only");
        assert_eq!(spec.wall_clock_ms, 120_000);
        assert!(spec.notes.iter().any(|n| n == "runtimeArguments ignored"));
        assert!(spec.notes.iter().any(|n| n.contains("NPM_CONFIG_REGISTRY")));
    }

    #[test]
    fn pypi_and_oci_specs() {
        let t = json!({"package": {"registryType": "pypi", "identifier": "acme-mcp", "version": "2.0",
            "registryBaseUrl": "https://ak.example.test/pypi/pypi-remote"}});
        let spec = guest_spec("j2", &t, AK, &Images::default()).unwrap();
        assert_eq!(
            spec.argv,
            [
                "uvx",
                "--no-config",
                "--default-index",
                "https://ak.example.test/pypi/pypi-remote/simple",
                "acme-mcp@2.0"
            ]
        );
        let t = json!({"package": {"registryType": "oci",
            "identifier": "ak.example.test/oci-local/acme/mcp:1.0@sha256:abc"}});
        let spec = guest_spec("j3", &t, AK, &Images::default()).unwrap();
        assert_eq!(
            spec.image,
            "ak.example.test/oci-local/acme/mcp:1.0@sha256:abc"
        );
        assert!(spec.argv.is_empty());
        assert_eq!(spec.network, "none");
    }

    #[test]
    fn specs_refuse_anything_not_from_ak() {
        let bad = [
            json!({}),
            json!({"package": {"registryType": "npm"}}),
            json!({"package": {"registryType": "npm", "identifier": "-x"}}),
            json!({"package": {"registryType": "npm", "identifier": "x", "version": "1",
                               "registryBaseUrl": "https://registry.npmjs.org"}}),
            json!({"package": {"registryType": "npm", "identifier": "x",
                               "registryBaseUrl": "https://ak.example.test/npm/r"}}),
            json!({"package": {"registryType": "oci", "identifier": "ghcr.io/acme/mcp@sha256:abc"}}),
            json!({"package": {"registryType": "oci", "identifier": "ak.example.test/oci/acme/mcp:1"}}),
            json!({"package": {"registryType": "cargo", "identifier": "x"}}),
        ];
        for t in bad {
            assert!(guest_spec("j", &t, AK, &Images::default()).is_err(), "{t}");
        }
        assert!(matches!(
            guest_spec(
                "j",
                &json!({"package": {"registryType": "nuget", "identifier": "x"}}),
                AK,
                &Images::default()
            ),
            Err(SandboxError::Unsupported(_))
        ));
    }

    #[test]
    fn oci_runner_renders_a_locked_down_run() {
        let spec = guest_spec("j1", &npm_target(), AK, &Images::default()).unwrap();
        let plan = OciRunner::default().plan(&spec).unwrap();
        assert_eq!(plan.program, "podman");
        for want in [
            "--rm",
            "-i",
            "--runtime=runsc",
            "--network=ak-mcp-sandbox",
            "--read-only",
            "--user=65532:65532",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=1g",
            "--cpus=1",
            "--log-driver=none",
            "--timeout=130",
            "--http-proxy=false",
            "--label=com.artifactkeeper.mcp-sandbox=j1",
            "--label=com.artifactkeeper.mcp-sandbox.owner=ak-mcp-introspector",
        ] {
            assert!(
                plan.args.iter().any(|a| a == want),
                "{want} missing: {:?}",
                plan.args
            );
        }
        assert!(!plan
            .args
            .iter()
            .any(|a| a.starts_with("-v") || a == "--privileged"));
        let img = plan.args.iter().position(|a| *a == spec.image).unwrap();
        assert_eq!(plan.args[img + 1], "npx");
        assert!(plan.args[..img]
            .iter()
            .any(|a| a == "API_KEY=AK_PLACEHOLDER_API_KEY"));
        // The container is removed after the run under the name it got, a
        // fresh one per attempt; a runner image is not pruned.
        let name = plan
            .args
            .iter()
            .find_map(|a| a.strip_prefix("--name="))
            .unwrap()
            .to_string();
        assert!(name.starts_with("ak-mcp-sbx-j1-"), "{name}");
        assert_eq!(
            plan.cleanup,
            [Cmd::new("podman", &["rm", "-f", &name])],
            "{:?}",
            plan.cleanup
        );
        let again = OciRunner::default().plan(&spec).unwrap();
        assert!(!again.args.iter().any(|a| *a == format!("--name={name}")));
        // Docker has no --timeout / --http-proxy.
        let docker = OciRunner {
            engine: "/usr/bin/docker".into(),
            ..Default::default()
        }
        .plan(&spec)
        .unwrap();
        assert!(docker.args.iter().any(|a| a == "--log-driver=none"));
        assert!(!docker
            .args
            .iter()
            .any(|a| a.starts_with("--timeout") || a.starts_with("--http-proxy")));
        assert_eq!(docker.cleanup[0].program, "/usr/bin/docker");
        // An OCI guest gets no network at all.
        let t = json!({"package": {"registryType": "oci",
            "identifier": "ak.example.test/oci/acme/mcp@sha256:abc"}});
        let spec = guest_spec("j3", &t, AK, &Images::default()).unwrap();
        let plan = OciRunner::default().plan(&spec).unwrap();
        assert!(plan.args.iter().any(|a| a == "--network=none"));
        // The job's own image is pruned after the container is removed.
        assert_eq!(plan.cleanup.len(), 2);
        assert_eq!(plan.cleanup[1], Cmd::new("podman", &["rmi", &spec.image]));
        // No runtime: refused unless the operator explicitly allows it.
        let r = OciRunner {
            runtime: String::new(),
            ..Default::default()
        };
        assert!(matches!(r.plan(&spec), Err(SandboxError::Unsupported(_))));
        let r = OciRunner {
            runtime: String::new(),
            allow_default_runtime: true,
            ..Default::default()
        };
        assert!(!r
            .plan(&spec)
            .unwrap()
            .args
            .iter()
            .any(|a| a.starts_with("--runtime")));
    }

    #[test]
    fn external_runner_and_env_configuration() {
        let spec = guest_spec("j1", &npm_target(), AK, &Images::default()).unwrap();
        let plan = ExternalRunner {
            command: "/opt/fc-run".into(),
        }
        .plan(&spec)
        .unwrap();
        assert_eq!(plan.program, "/opt/fc-run");
        let decoded: Value = serde_json::from_str(&plan.args[0]).unwrap();
        assert_eq!(decoded["jobId"], "j1");
        assert_eq!(decoded["network"], "ak-only");
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(
            runner_from_env(env(&[("AK_MCP_SANDBOX_COMMAND", "/x")]), "w").name(),
            "external"
        );
        let r = runner_from_env(
            env(&[
                ("AK_MCP_SANDBOX_ENGINE", "docker"),
                ("AK_MCP_SANDBOX_RUNTIME", "kata-fc"),
            ]),
            "host-1",
        );
        assert_eq!(r.name(), "oci");
        let p = r.plan(&spec).unwrap();
        assert_eq!(p.program, "docker");
        assert!(p.args.iter().any(|a| a == "--runtime=kata-fc"));
        assert!(p
            .args
            .iter()
            .any(|a| a == "--label=com.artifactkeeper.mcp-sandbox.owner=host-1"));
        assert_eq!(
            images_from_env(env(&[("AK_MCP_SANDBOX_NODE_IMAGE", "ak/node")])).node,
            "ak/node"
        );
        assert_eq!(placeholder(""), "AK_PLACEHOLDER_VALUE");
        assert!(SandboxError::Invalid("x".into()).to_string() == "x");
    }

    #[test]
    fn only_sandbox_runtimes_pass_without_the_allow_flag() {
        let spec = guest_spec("j1", &npm_target(), AK, &Images::default()).unwrap();
        for ok in [
            "runsc",
            "/usr/local/bin/runsc",
            "runsc-debug",
            "kata-fc",
            "kata-qemu",
            "io.containerd.kata.v2",
            "io.containerd.runsc.v1",
        ] {
            assert!(is_sandbox_runtime(ok), "{ok}");
            let r = OciRunner {
                runtime: ok.into(),
                ..Default::default()
            };
            assert!(r.plan(&spec).is_ok(), "{ok}");
        }
        for plain in [
            "",
            "runc",
            "crun",
            "/usr/bin/crun",
            "youki",
            "io.containerd.runc.v2",
        ] {
            assert!(!is_sandbox_runtime(plain), "{plain}");
            let r = OciRunner {
                runtime: plain.into(),
                ..Default::default()
            };
            let Err(SandboxError::Unsupported(m)) = r.plan(&spec) else {
                panic!("{plain} must be refused");
            };
            assert!(m.contains("AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME"), "{m}");
            let r = OciRunner {
                runtime: plain.into(),
                allow_default_runtime: true,
                ..Default::default()
            };
            assert!(r.plan(&spec).is_ok(), "{plain} with the allow flag");
        }
    }

    #[test]
    fn default_images_are_pinned_by_digest() {
        assert!(Images::default().unpinned().is_empty());
        let i = Images {
            node: "docker.io/library/node:22-alpine".into(),
            ..Default::default()
        };
        assert_eq!(i.unpinned(), ["docker.io/library/node:22-alpine"]);
    }

    /// The engine never sees the worker's token, only what it needs.
    #[test]
    fn the_engine_gets_a_cleared_environment() {
        let vars = [
            ("PATH", "/usr/bin"),
            ("XDG_RUNTIME_DIR", "/run/user/1500"),
            ("AK_MCP_INTROSPECTOR_TOKEN", "secret"),
            ("AK_TOKEN", "secret"),
            ("AK_URL", "https://ak"),
            ("DATABASE_URL", "postgres://x"),
            ("AK_MCP_SANDBOX_NAMESPACE", "sbx"),
            ("EXTRA_ONE", "1"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let names = |pass| {
            engine_env(vars.clone(), pass)
                .into_iter()
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(None),
            ["PATH", "XDG_RUNTIME_DIR", "AK_MCP_SANDBOX_NAMESPACE"]
        );
        assert_eq!(
            names(Some("EXTRA_ONE, AK_MCP_INTROSPECTOR_TOKEN,AK_TOKEN")),
            [
                "PATH",
                "XDG_RUNTIME_DIR",
                "AK_MCP_SANDBOX_NAMESPACE",
                "EXTRA_ONE"
            ]
        );
    }

    fn sh(script: &str) -> RunPlan {
        RunPlan {
            program: "sh".into(),
            args: vec!["-c".into(), script.into()],
            cleanup: Vec::new(),
        }
    }

    fn scratch() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ak-sbx-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn run_and_probe_reports_start_failures() {
        let plan = RunPlan {
            program: "/nonexistent/ak-sandbox".into(),
            ..Default::default()
        };
        assert_eq!(run_and_probe(&plan, 10, 1024).await.outcome, "start_failed");
        // A guest that exits at once: the server would not start unconfigured.
        assert_eq!(
            run_and_probe(&sh("exit 0"), 10, 1024).await.outcome,
            "needs_config"
        );
        assert_eq!(
            run_and_probe(&sh("exit 3"), 10, 1024).await.outcome,
            "needs_config"
        );
    }

    /// The engine failing (exit 125: name in use, runtime or network
    /// missing, pull failed; 126/127) is the sandbox's failure, retried, not
    /// the server's `needs_config`; the engine's message is the error.
    #[tokio::test]
    async fn engine_failures_are_start_failed_not_needs_config() {
        for code in [125, 126, 127] {
            let r = run_and_probe(
                &sh(&format!(
                    "echo 'Error: the container name \"ak-mcp-sbx-j\" is already in use' >&2; exit {code}"
                )),
                10,
                1024,
            )
            .await;
            assert_eq!(r.outcome, "start_failed", "exit {code}: {r:?}");
            let e = r.error.unwrap();
            assert!(e.contains(&format!("exit {code}")), "{e}");
            assert!(e.contains("already in use"), "{e}");
            assert_eq!(r.details["exitCode"], code);
        }
    }

    /// A guest that ignores SIGTERM and never answers: the wall clock ends
    /// the run, and the plan's cleanup (what removes the container) runs
    /// after it, also after a timeout.
    #[tokio::test]
    async fn cleanup_runs_after_every_run_including_timeouts() {
        let dir = scratch();
        let marker = dir.join("removed");
        let mut plan = sh("trap '' TERM; read _; exec sleep 60");
        plan.cleanup = vec![Cmd::new(
            "sh",
            &["-c", &format!("echo gone > {}", marker.display())],
        )];
        let started = std::time::Instant::now();
        let r = run_and_probe_within(&plan, 10, 1024, Duration::from_secs(1)).await;
        assert_eq!(r.outcome, "timeout", "{r:?}");
        assert!(marker.exists(), "cleanup ran after the timeout");
        assert!(started.elapsed() < Duration::from_secs(20));
        std::fs::remove_file(&marker).unwrap();
        let mut plan = sh("exit 0");
        plan.cleanup = vec![Cmd::new(
            "sh",
            &["-c", &format!("echo gone > {}", marker.display())],
        )];
        run_and_probe(&plan, 10, 1024).await;
        assert!(marker.exists(), "cleanup ran after an early exit");
    }

    /// Startup reaping lists this worker's guests by its owner label and
    /// removes them.
    #[tokio::test]
    async fn leftover_guests_are_reaped() {
        let dir = scratch();
        let log = dir.join("calls");
        let engine = dir.join("engine");
        std::fs::write(
            &engine,
            format!(
                "#!/bin/sh\necho \"$*\" >> {}\ncase \"$1\" in ps) printf 'c1\\nc2\\n';; esac\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = OciRunner {
            engine: engine.to_string_lossy().into_owned(),
            owner: "host-1".into(),
            ..Default::default()
        };
        assert_eq!(reap_leftovers(&r).await, Ok(2));
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls,
            "ps -a -q --filter label=com.artifactkeeper.mcp-sandbox.owner=host-1\nrm -f c1 c2\n"
        );
        assert_eq!(
            reap_leftovers(&ExternalRunner {
                command: "/x".into()
            })
            .await,
            Ok(0)
        );
    }
}
