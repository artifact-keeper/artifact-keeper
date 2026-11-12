//! Sandboxed stdio introspection (Phase 3): a pluggable [`SandboxRunner`].
//!
//! A sandbox job names one stdio package of a server version as AK serves
//! it (`registryBaseUrl` / OCI identifier rewritten to this AK instance).
//! [`guest_spec`] turns it into a runner-neutral [`GuestSpec`]: which image,
//! which command, which environment. The rules it applies:
//!
//! * install only from AK: `npx --registry=<registryBaseUrl>`, `uvx
//!   --default-index <registryBaseUrl>/simple`, or a canonical AK-served OCI
//!   reference with exactly one lower-case SHA-256 digest; an OCI package's
//!   legacy source fields are refused. Publisher `runtimeArguments` are
//!   dropped (they are where `--registry` and `-v /:/host` would go), and
//!   environment variables that steer a
//!   package manager (`NPM_CONFIG_*`, `UV_*`, `PIP_*`, ...) are refused;
//! * no real secrets: every `isSecret` value, every required value without
//!   a default, and every `{template}` value becomes `AK_PLACEHOLDER_<NAME>`;
//! * the guest's network is `none` for an OCI image (already pulled by the
//!   engine); an npm or PyPI guest gets a network of its own, created for
//!   the run as an internal network whose only other member is the AK
//!   forwarder, and removed after it (#5447). Guests never share a network,
//!   so one guest cannot reach another; the run is refused if that network
//!   cannot be created or the forwarder cannot join it;
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

use artifact_keeper_backend::formats::mcp::{host_of, parse_oci_reference, OciRefError};
use serde::Serialize;
use serde_json::Value;

mod source;

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
    /// The sandbox deployment, not the job, cannot run it (no forwarder
    /// configured, an AK base URL the forwarder cannot stand in for):
    /// reported `start_failed`, so the job is retried, not stored as the
    /// server's state.
    Deployment(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Unsupported(m)
            | SandboxError::Invalid(m)
            | SandboxError::Deployment(m) => {
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
/// With `credential_names` (npm and PyPI guests), an input whose name ends in
/// a credential word (`*_TOKEN`, `--password`, ...) gets a placeholder even
/// when the publisher did not mark it secret.
fn input_value(input: &Value, label: &str, credential_names: bool) -> Option<String> {
    let given = s(input, "value").or_else(|| s(input, "default"));
    let credential =
        credential_names && s(input, "name").is_some_and(source::looks_like_credential);
    if flag(input, "isSecret") || credential || given.is_some_and(|g| g.contains('{')) {
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
pub fn guest_env(
    package: &Value,
    credential_names: bool,
    notes: &mut Vec<String>,
) -> Vec<(String, String)> {
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
        if let Some(v) = input_value(var, name, credential_names) {
            env.retain(|(k, _)| k != name);
            env.push((name.to_string(), v));
        }
    }
    env
}

/// The package's `packageArguments` for the guest command.
pub fn package_args(package: &Value, credential_names: bool) -> Vec<String> {
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
                if let Some(v) = input_value(a, &label, credential_names) {
                    out.push(name.to_string());
                    out.push(v);
                } else if flag(a, "isRequired") || a.get("value").is_none() {
                    out.push(name.to_string());
                }
            }
            _ => {
                if let Some(v) = input_value(a, &label, credential_names) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The one image an OCI job may run: a canonical reference on the job's AK
/// origin with exactly one SHA-256 digest. The returned string is handed to
/// the engine verbatim, so no other field or argument can choose the source.
fn oci_image(identifier: &str, ak_base_url: &str) -> Result<String, SandboxError> {
    let invalid = |m: &str| SandboxError::Invalid(format!("OCI identifier: {m}"));
    let base = url::Url::parse(ak_base_url)
        .map_err(|_| SandboxError::Invalid("AK base URL is not a URL".into()))?;
    if base.host_str().is_none() {
        return Err(SandboxError::Invalid("AK base URL has no host".into()));
    }
    let ak_host = host_of(ak_base_url);
    // An image reference only names a registry host whose first component
    // contains `.` or `:` or is `localhost`; any other first component is a
    // Docker Hub namespace, so a bare service name can never be this AK.
    if !(ak_host.contains('.') || ak_host.contains(':') || ak_host == "localhost") {
        return Err(SandboxError::Invalid(format!(
            "AK host `{ak_host}` cannot name an OCI registry: it must contain `.` or `:`, \
             or be `localhost`"
        )));
    }
    if identifier.matches('@').count() != 1 {
        return Err(invalid("exactly one `@sha256:<digest>` is required"));
    }
    // `parse_oci_reference` resolves a floating tag rather than refusing it,
    // so `Invalid` is the only error it returns.
    let (image, _) = parse_oci_reference(identifier).map_err(|e| {
        invalid(match &e {
            OciRefError::Invalid(m) => m,
            OciRefError::Floating => "not an image reference",
        })
    })?;
    // The parser has checked the digest's length and lower-case hex; only
    // the algorithm is left.
    let digest = image
        .digest
        .as_deref()
        .filter(|d| d.starts_with("sha256:"))
        .ok_or_else(|| invalid("the digest must be SHA-256"))?;
    if image.host != ak_host {
        return Err(invalid("the image host is not this AK instance"));
    }
    // An AK OCI reference is `<ak host>/<repository>/<name>[...]`; a bare
    // image name is not a repository path this instance serves.
    if image.path.split('/').count() < 2 {
        return Err(invalid("the path is not an AK repository/image path"));
    }
    let mut canonical = format!("{}/{}", image.host, image.path);
    if let Some(tag) = &image.tag {
        canonical.push(':');
        canonical.push_str(tag);
    }
    canonical.push('@');
    canonical.push_str(digest);
    if canonical != identifier {
        return Err(invalid("the reference is not canonical"));
    }
    Ok(canonical)
}

/// OCI keeps its source in `identifier`. Refuse the legacy source fields
/// instead of letting a second value compete with the validated reference.
/// (Publisher `runtimeArguments` are dropped with a note, as for npm/PyPI:
/// the engine arguments are fixed by the runner.)
fn reject_oci_source_overrides(package: &Value) -> Result<(), SandboxError> {
    for field in ["version", "registryBaseUrl", "fileSha256"] {
        if package.get(field).is_some_and(|v| !v.is_null()) {
            return Err(SandboxError::Invalid(format!(
                "OCI package must put its tag or digest in `identifier`, not `{field}`"
            )));
        }
    }
    Ok(())
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
    let ak = ak_base_url.trim_end_matches('/');
    source::ak_base(ak)?;
    // npm and PyPI install from the AK registry only (#5446): whatever could
    // name another source is refused here, before a runner sees the spec.
    let confined = matches!(kind, "npm" | "pypi");
    if confined {
        source::check_coordinates(kind, identifier, s(package, "version"))?;
        let runtime = source::raw_arg_tokens(package, "runtimeArguments");
        source::check_args(kind, "runtimeArguments", &runtime)?;
        source::check_env(kind, package)?;
    }
    if package
        .get("runtimeArguments")
        .and_then(|a| a.as_array())
        .is_some_and(|a| !a.is_empty())
    {
        notes.push("runtimeArguments ignored".into());
    }
    let env = guest_env(package, confined, &mut notes);
    let args = package_args(package, confined);
    if confined {
        source::check_args(kind, "packageArguments", &args)?;
    }
    let registry = || source::registry_url(kind, s(package, "registryBaseUrl"), ak);
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
            reject_oci_source_overrides(package)?;
            (oci_image(identifier, ak)?, Vec::new(), "none")
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
    /// Run in order before the guest; each must succeed, or the guest is
    /// not started (`start_failed`) and the cleanup runs. This is where the
    /// guest's own network is created and the forwarder joins it: a guest
    /// never starts without the network that isolates it.
    pub setup: Vec<Cmd>,
    /// Run after `setup`: the forwarder's address on the guest's network,
    /// which the guest gets as an `/etc/hosts` entry for AK's host name
    /// (`--add-host`). The guest does not depend on the engine's DNS for
    /// it, which a gVisor guest on an internal Docker network cannot reach.
    /// An address that cannot be read stops the run like a failed setup.
    pub host_lookup: Option<HostLookup>,
    pub program: String,
    pub args: Vec<String>,
    /// Run after the guest, whatever the outcome: remove the container
    /// (the engine client exiting does not stop it), its network, and
    /// prune the job's own image.
    pub cleanup: Vec<Cmd>,
}

/// How to find the address `host` should resolve to in the guest: `cmd`
/// prints it (one IP address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLookup {
    pub host: String,
    pub cmd: Cmd,
}

/// `args` (an engine `run` command line, `args[0] == "run"`) with
/// `--add-host=<host>:<ip>` added among the run options, before the image.
pub fn with_host_entry(args: &[String], host: &str, ip: &str) -> Vec<String> {
    let mut out = args.to_vec();
    out.insert(1.min(out.len()), format!("--add-host={host}:{ip}"));
    out
}

/// The IP address a lookup command printed, or why there is none.
pub fn parse_lookup_ip(stdout: &str) -> Result<String, String> {
    let text = stdout.trim();
    match text.parse::<std::net::IpAddr>() {
        Ok(ip) if !ip.is_unspecified() => Ok(ip.to_string()),
        _ => Err(format!("printed `{text}`, not an IP address")),
    }
}

/// Leftover guests of this worker: `list` prints one container id per
/// line, `remove` (with the ids appended) removes them. `networks`, when
/// the runner creates any, prints one leftover guest network per line;
/// each is torn down with [`SandboxRunner::network_teardown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reap {
    pub list: Cmd,
    pub remove: Cmd,
    pub networks: Option<Cmd>,
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
    /// The commands that remove the guest network `network` (detach the
    /// forwarder, then remove the network). Empty: the runner creates none.
    fn network_teardown(&self, _network: &str) -> Vec<Cmd> {
        Vec::new()
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
    /// The container of the AK forwarder (`AK_MCP_SANDBOX_GATEWAY`, default
    /// `ak-gateway`). Every npm or PyPI guest gets an internal network of
    /// its own, and this container joins it under the AK hostname.
    pub gateway: String,
    pub memory: String,
    pub cpus: String,
    pub pids_limit: u32,
    pub tmpfs_size: String,
    pub allow_default_runtime: bool,
    /// The worker id, as the [`OWNER_LABEL`] of every guest it starts.
    pub owner: String,
}

/// The forwarder's container name in `compose.sandbox-network.yaml`.
pub const DEFAULT_GATEWAY: &str = "ak-gateway";

/// The host part of the job's AK base URL (`akBaseUrl`, the backend's
/// public base URL; the worker's `AK_URL` only when the job has none), the
/// name the forwarder answers on in a guest network. An IP literal is a
/// [`SandboxError::Deployment`] error: the guest would connect to it
/// directly, and an internal network has no route to it.
pub fn gateway_alias(ak_base_url: &str) -> Result<String, SandboxError> {
    let url = url::Url::parse(ak_base_url)
        .map_err(|e| SandboxError::Invalid(format!("AK URL `{ak_base_url}`: {e}")))?;
    match url.host() {
        Some(url::Host::Domain(d)) if !d.is_empty() => Ok(d.to_string()),
        Some(_) => Err(SandboxError::Deployment(format!(
            "AK base URL `{ak_base_url}` names an IP address; an npm or PyPI guest reaches \
             AK through the forwarder under AK's host name, so the backend's public base \
             URL must use one"
        ))),
        None => Err(SandboxError::Invalid(format!(
            "AK URL `{ak_base_url}` has no host"
        ))),
    }
}

impl Default for OciRunner {
    fn default() -> Self {
        Self {
            engine: "podman".into(),
            runtime: "runsc".into(),
            gateway: DEFAULT_GATEWAY.into(),
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

    fn labels(&self, job: &str) -> [String; 2] {
        [
            format!("--label={SANDBOX_LABEL}={job}"),
            format!("--label={OWNER_LABEL}={}", name_part(&self.owner, 128)),
        ]
    }

    /// The command that prints the forwarder's address on `network`. The
    /// `NetworkSettings.Networks.<name>.IPAddress` template works with both
    /// Docker and Podman `container inspect`.
    fn gateway_ip_lookup(&self, network: &str) -> Cmd {
        let format = format!("{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}");
        Cmd::new(
            &self.engine,
            &["container", "inspect", "--format", &format, &self.gateway],
        )
    }

    /// The commands that give a guest its own network `network`: an
    /// internal network (no route out, no other guest), labelled like the
    /// guest so a crashed worker's leftovers are reaped, which the
    /// forwarder then joins under the AK hostname `alias`. Either failing
    /// aborts the run.
    fn network_setup(&self, network: &str, job: &str, alias: &str) -> Vec<Cmd> {
        let mut create: Vec<String> = vec!["network".into(), "create".into(), "--internal".into()];
        create.extend(self.labels(job));
        create.push(network.into());
        vec![
            Cmd {
                program: self.engine.clone(),
                args: create,
            },
            Cmd::new(
                &self.engine,
                &[
                    "network",
                    "connect",
                    "--alias",
                    alias,
                    network,
                    &self.gateway,
                ],
            ),
        ]
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
        // A fresh name per attempt: a retry never collides with a guest of
        // an earlier attempt that is still being removed. The guest's own
        // network (npm, PyPI) carries the same name.
        let job = name_part(&spec.job_id, 64);
        let name = format!(
            "ak-mcp-sbx-{job}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let (network, setup, setup_alias) = match spec.network.as_str() {
            "none" => ("none".to_string(), Vec::new(), None),
            _ => {
                if self.gateway.trim().is_empty() {
                    return Err(SandboxError::Deployment(
                        "AK_MCP_SANDBOX_GATEWAY is empty: npm and PyPI guests reach AK only \
                         through the forwarder"
                            .into(),
                    ));
                }
                let alias = gateway_alias(&spec.ak_base_url)?;
                let setup = self.network_setup(&name, &job, &alias);
                (name.clone(), setup, Some(alias))
            }
        };
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "-i".into(),
            format!("--name={name}"),
        ];
        args.extend(self.labels(&job));
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
        if !setup.is_empty() {
            cleanup.extend(self.network_teardown(&name));
        }
        if spec.prune_image {
            cleanup.push(Cmd::new(&self.engine, &["rmi", &spec.image]));
        }
        let host_lookup = setup_alias.map(|host| HostLookup {
            host,
            cmd: self.gateway_ip_lookup(&name),
        });
        Ok(RunPlan {
            setup,
            host_lookup,
            program: self.engine.clone(),
            args,
            cleanup,
        })
    }

    fn reap(&self) -> Option<Reap> {
        let filter = self.owner_filter();
        Some(Reap {
            list: Cmd::new(&self.engine, &["ps", "-a", "-q", "--filter", &filter]),
            remove: Cmd::new(&self.engine, &["rm", "-f"]),
            networks: Some(Cmd::new(
                &self.engine,
                &["network", "ls", "-q", "--filter", &filter],
            )),
        })
    }

    /// Detach the forwarder, then remove the network. Never `network rm
    /// -f`: that removes every container on the network, the forwarder
    /// included.
    fn network_teardown(&self, network: &str) -> Vec<Cmd> {
        vec![
            Cmd::new(
                &self.engine,
                &["network", "disconnect", "-f", network, &self.gateway],
            ),
            Cmd::new(&self.engine, &["network", "rm", network]),
        ]
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
            ..Default::default()
        })
    }
}

/// The runner the environment configures: `AK_MCP_SANDBOX_COMMAND` selects
/// an [`ExternalRunner`], otherwise an [`OciRunner`] from
/// `AK_MCP_SANDBOX_ENGINE` / `_RUNTIME` / `_GATEWAY` / `_MEMORY` / `_CPUS`,
/// labelling its guests with `owner` (the worker id).
///
/// A configuration that cannot isolate guests is an error, and the worker
/// does not start: the retired `AK_MCP_SANDBOX_NETWORK` (a shared guest
/// network, #5447) or an empty `AK_MCP_SANDBOX_GATEWAY`. Refusing per job
/// instead would let a running worker claim and fail every job.
pub fn runner_from_env(
    get: impl Fn(&str) -> Option<String>,
    owner: &str,
) -> Result<Box<dyn SandboxRunner>, String> {
    if let Some(command) = get("AK_MCP_SANDBOX_COMMAND").filter(|c| !c.is_empty()) {
        return Ok(Box::new(ExternalRunner { command }));
    }
    if let Some(net) = get("AK_MCP_SANDBOX_NETWORK").filter(|n| !n.is_empty()) {
        return Err(format!(
            "AK_MCP_SANDBOX_NETWORK={net} is no longer supported: guests that share a network \
             can reach each other (#5447). Unset it (and remove that network); every npm or \
             PyPI guest now gets an internal network of its own that only the forwarder \
             (AK_MCP_SANDBOX_GATEWAY, default `{DEFAULT_GATEWAY}`) joins. \
             docs/security/mcp-sandbox.md, \"Guest networks\""
        ));
    }
    let d = OciRunner::default();
    let r = OciRunner {
        engine: get("AK_MCP_SANDBOX_ENGINE").unwrap_or(d.engine),
        runtime: get("AK_MCP_SANDBOX_RUNTIME").unwrap_or(d.runtime),
        gateway: get("AK_MCP_SANDBOX_GATEWAY").unwrap_or(d.gateway),
        memory: get("AK_MCP_SANDBOX_MEMORY").unwrap_or(d.memory),
        cpus: get("AK_MCP_SANDBOX_CPUS").unwrap_or(d.cpus),
        allow_default_runtime: get("AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME").as_deref()
            == Some("true"),
        owner: owner.to_string(),
        ..d
    };
    if r.gateway.trim().is_empty() {
        return Err(
            "AK_MCP_SANDBOX_GATEWAY is empty: npm and PyPI guests reach AK only through the \
             forwarder container it names (default `ak-gateway`)"
                .into(),
        );
    }
    Ok(Box::new(r))
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

/// Run a short engine command (setup, cleanup, listing) to completion
/// within `limit`; its exit status and output when it ran.
async fn run_cmd(cmd: &Cmd, limit: Duration) -> Option<std::process::Output> {
    let child = command(&cmd.program, &cmd.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    tokio::time::timeout(limit, child.wait_with_output())
        .await
        .ok()?
        .ok()
}

/// The start of a command's stderr, for an error or a warning.
fn stderr_head(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(STDERR_KEEP)])
        .trim()
        .to_string()
}

/// Run a plan's setup and host lookup: the plan to start, with the
/// forwarder's `--add-host` entry, or why the guest must not start.
async fn prepare(plan: &RunPlan) -> Result<RunPlan, String> {
    run_setup(&plan.setup).await?;
    let Some(lookup) = &plan.host_lookup else {
        return Ok(plan.clone());
    };
    let line = format!("{} {}", lookup.cmd.program, lookup.cmd.args.join(" "));
    let ip = match run_cmd(&lookup.cmd, CLEANUP_TIMEOUT).await {
        Some(out) if out.status.success() => parse_lookup_ip(&String::from_utf8_lossy(&out.stdout)),
        Some(out) => Err(format!("{}: {}", out.status, stderr_head(&out))),
        None => Err("could not be run or timed out".into()),
    }
    .map_err(|why| {
        format!(
            "the forwarder's address on the guest network could not be read, so the guest \
             was not started: `{line}` failed ({why})"
        )
    })?;
    Ok(RunPlan {
        args: with_host_entry(&plan.args, &lookup.host, &ip),
        ..plan.clone()
    })
}

/// Run a plan's setup commands in order, stopping at the first that does
/// not succeed: why it failed, with the start of its stderr.
async fn run_setup(setup: &[Cmd]) -> Result<(), String> {
    for cmd in setup {
        let why = match run_cmd(cmd, CLEANUP_TIMEOUT).await {
            Some(out) if out.status.success() => continue,
            Some(out) => {
                let err = stderr_head(&out);
                format!(
                    "{}{}{err}",
                    out.status,
                    if err.is_empty() { "" } else { ": " }
                )
            }
            None => "could not be run or timed out".into(),
        };
        return Err(format!(
            "the guest network could not be prepared, so the guest was not started: `{} {}` \
             failed ({why})",
            cmd.program,
            cmd.args.join(" ")
        ));
    }
    Ok(())
}

/// Remove the guests a previous run of this worker left behind. The number
/// removed, or why that could not be checked.
pub async fn reap_leftovers(runner: &dyn SandboxRunner) -> Result<usize, String> {
    let Some(reap) = runner.reap() else {
        return Ok(0);
    };
    let ids = list_lines(&reap.list, "guests").await?;
    if !ids.is_empty() {
        let mut remove = reap.remove.clone();
        remove.args.extend(ids.iter().cloned());
        match run_cmd(&remove, CLEANUP_TIMEOUT).await {
            Some(out) if out.status.success() => {}
            _ => return Err(format!("removing {} leftover guest(s) failed", ids.len())),
        }
    }
    // The guests' own networks, once no guest uses them.
    if let Some(list) = &reap.networks {
        for net in list_lines(list, "guest networks").await? {
            for cmd in runner.network_teardown(&net) {
                run_logged(&cmd, "leftover guest network teardown").await;
            }
        }
    }
    Ok(ids.len())
}

/// Run a cleanup or teardown command; warn, naming it, when it could not be
/// run or exited non-zero. Whether it succeeded.
async fn run_logged(cmd: &Cmd, what: &str) -> bool {
    let line = format!("{} {}", cmd.program, cmd.args.join(" "));
    match run_cmd(cmd, CLEANUP_TIMEOUT).await {
        Some(out) if out.status.success() => true,
        Some(out) => {
            let err = stderr_head(&out);
            tracing::warn!(command = %line, status = %out.status, stderr = %err, "{what} failed");
            false
        }
        None => {
            tracing::warn!(command = %line, "{what} did not run");
            false
        }
    }
}

/// The non-empty lines `list` prints, or why it could not be listed.
async fn list_lines(list: &Cmd, what: &str) -> Result<Vec<String>, String> {
    let out = run_cmd(list, CLEANUP_TIMEOUT)
        .await
        .ok_or_else(|| format!("`{}` could not be run", list.program))?;
    if !out.status.success() {
        return Err(format!("listing leftover {what} failed ({})", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
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
    let report = match prepare(plan).await {
        Ok(ready) => probe_child(&ready, max_items, max_bytes, wall_clock).await,
        Err(e) => crate::protocol::ProbeReport {
            outcome: "start_failed".into(),
            auth_state: "none".into(),
            error: Some(e),
            ..Default::default()
        },
    };
    for cmd in &plan.cleanup {
        run_logged(cmd, "sandbox cleanup").await;
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

    fn oci_digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn npm_target() -> Value {
        json!({"type": "package", "index": 0, "registryType": "npm", "package": {
            "registryType": "npm", "identifier": "@acme/weather", "version": "1.2.3",
            "registryBaseUrl": "https://ak.example.test/npm/npm-virtual",
            "transport": {"type": "stdio"},
            "runtimeArguments": [{"type": "named", "name": "-v", "value": "/:/host-evil"}],
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
                {"name": "LD_PRELOAD", "value": "/tmp/evil.so"},
                {"name": "PATH", "value": "/tmp/evil"},
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
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("PATH"));
        assert_eq!(
            env["npm_config_registry"],
            "https://ak.example.test/npm/npm-virtual"
        );
        assert_eq!(env["HOME"], "/tmp/home");
        assert_eq!(spec.network, "ak-only");
        assert_eq!(spec.wall_clock_ms, 120_000);
        assert!(spec.notes.iter().any(|n| n == "runtimeArguments ignored"));
        assert!(spec.notes.iter().any(|n| n.contains("LD_PRELOAD")));
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
        let identifier = format!("ak.example.test/oci-local/acme/mcp:1.0@{}", oci_digest());
        let t = json!({"package": {"registryType": "oci", "identifier": identifier}});
        let spec = guest_spec("j3", &t, AK, &Images::default()).unwrap();
        assert_eq!(spec.image, identifier);
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
            json!({"package": {"registryType": "oci",
                               "identifier": format!("ghcr.io/acme/mcp@{}", oci_digest())}}),
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
    fn oci_spec_refuses_malformed_references_and_source_overrides() {
        let d = "a".repeat(64);
        let bad = vec![
            // Malformed digest.
            format!("ak.example.test/oci/acme/mcp@sha256:{}", &d[..63]),
            format!("ak.example.test/oci/acme/mcp@sha256:{}", "a".repeat(65)),
            format!("ak.example.test/oci/acme/mcp@sha256:{}", "A".repeat(64)),
            format!("ak.example.test/oci/acme/mcp@sha256:{}", "g".repeat(64)),
            "ak.example.test/oci/acme/mcp@sha256:abc".to_string(),
            format!("ak.example.test/oci/acme/mcp@sha512:{}", "a".repeat(128)),
            format!("ak.example.test/oci/acme/mcp@md5:{}", "a".repeat(32)),
            format!("ak.example.test/oci/acme/mcp@sha256:{d}:x"),
            // More than one digest delimiter, or trailing data.
            format!("ak.example.test/oci/acme/mcp@sha256:{d}@sha256:{d}"),
            format!("ak.example.test/oci/acme/mcp@sha256:{d}@"),
            format!("ak.example.test/oci/acme/mcp@@sha256:{d}"),
            format!("ak.example.test/oci/acme/mcp@sha256:{d}@evil"),
            // Unsafe, ambiguous or non-canonical repository paths.
            format!("ak.example.test/../acme/mcp@sha256:{d}"),
            format!("ak.example.test/oci//acme/mcp@sha256:{d}"),
            format!("ak.example.test/oci/./acme/mcp@sha256:{d}"),
            format!("ak.example.test/oci/acme/../mcp@sha256:{d}"),
            format!("ak.example.test/oci/Acme/mcp@sha256:{d}"),
            format!("ak.example.test/oci/acme/mcp%2f..@sha256:{d}"),
            format!("ak.example.test\\oci\\acme\\mcp@sha256:{d}"),
            format!("/ak.example.test/oci/acme/mcp@sha256:{d}"),
            format!("ak.example.test/oci/acme/mcp/@sha256:{d}"),
            format!("ak.example.test/oci/acme/mcp@sha256:{d}\n"),
            format!("ak.example.test/oci/acme/mcp@sha256:{d} --network=host"),
            format!("ak.example.test/oci/acme/mcp:1:2@sha256:{d}"),
            // Not an AK repository/image path.
            format!("ak.example.test/mcp@sha256:{d}"),
            // Another origin, including host-prefix and user-info confusion.
            format!("ak.example.test.evil/oci/acme/mcp@sha256:{d}"),
            format!("evil.test/ak.example.test/oci/acme/mcp@sha256:{d}"),
            format!("AK.EXAMPLE.TEST/oci/acme/mcp@sha256:{d}"),
            format!("ak.example.test@evil/oci/acme/mcp@sha256:{d}"),
            format!("ak.example.test:8443/oci/acme/mcp@sha256:{d}"),
            format!("localhost/oci/acme/mcp@sha256:{d}"),
        ];
        for id in bad {
            let t = json!({"package": {"registryType": "oci", "identifier": id}});
            assert!(guest_spec("j", &t, AK, &Images::default()).is_err(), "{id}");
        }

        let canonical = format!("ak.example.test/oci/acme/mcp@{}", oci_digest());
        for field in ["version", "registryBaseUrl", "fileSha256"] {
            let mut package = json!({"registryType": "oci", "identifier": canonical.clone()});
            package
                .as_object_mut()
                .unwrap()
                .insert(field.into(), json!("https://evil.test"));
            assert!(
                guest_spec("j", &json!({"package": package}), AK, &Images::default()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn oci_spec_drops_runtime_arguments_like_npm_and_pypi() {
        // Docker-style server.json files carry `-e VAR=...` and mounts; publish
        // accepts them, so the job must still run, with them dropped.
        let canonical = format!("ak.example.test/oci/acme/mcp@{}", oci_digest());
        let t = json!({"package": {
            "registryType": "oci", "identifier": canonical.clone(),
            "runtimeArguments": [
                {"type": "named", "name": "-e", "value": "EVIL_VAR=1"},
                {"type": "named", "name": "-v", "value": "/:/host"},
                {"type": "named", "name": "--image", "value": "evil.test/x"},
                {"type": "named", "name": "--registry", "value": "https://evil.test"},
                {"type": "positional", "value": "--pull=always"},
            ],
        }});
        let spec = guest_spec("j", &t, AK, &Images::default()).unwrap();
        assert_eq!(spec.image, canonical);
        assert!(spec.argv.is_empty());
        assert!(spec.notes.iter().any(|n| n == "runtimeArguments ignored"));
        let plan = OciRunner::default().plan(&spec).unwrap();
        // The runner passes its own `-e NAME=value` pairs; none of the
        // publisher's names, values or flags is among the engine arguments.
        assert!(!plan.args.iter().any(|a| a == "-v"));
        for dropped in [
            "EVIL_VAR",
            "/:/host",
            "--image",
            "evil.test",
            "--registry",
            "--pull=always",
        ] {
            assert!(
                !plan.args.iter().any(|a| a.contains(dropped)),
                "{dropped} reached the engine: {:?}",
                plan.args
            );
        }
    }

    fn oci_err(identifier: &str, ak: &str) -> String {
        let t = json!({"package": {"registryType": "oci", "identifier": identifier}});
        match guest_spec("j", &t, ak, &Images::default()) {
            Err(SandboxError::Invalid(m)) => m,
            other => panic!("{identifier} on {ak}: expected Invalid, got {other:?}"),
        }
    }

    fn oci_ok(identifier: &str, ak: &str) -> String {
        let t = json!({"package": {"registryType": "oci", "identifier": identifier}});
        guest_spec("j", &t, ak, &Images::default())
            .unwrap_or_else(|e| panic!("{identifier} on {ak}: {e}"))
            .image
    }

    #[test]
    fn oci_spec_refuses_an_unusable_ak_base_url() {
        let id = format!("ak.example.test/oci/acme/mcp@{}", oci_digest());
        assert_eq!(oci_err(&id, "not a url"), "AK base URL is not a URL");
        assert_eq!(oci_err(&id, "unix:/run/ak.sock"), "AK base URL has no host");
        // A bare service name is read as a Docker Hub namespace by every
        // image-reference parser, so it can never name this AK as a registry.
        let d = oci_digest();
        for (base, id) in [
            (
                "http://artifact-keeper",
                format!("artifact-keeper/oci/acme/mcp@{d}"),
            ),
            ("https://ak:443", format!("ak/oci/acme/mcp@{d}")),
            ("https://ak:443", format!("ak:443/oci/acme/mcp@{d}")),
        ] {
            let m = oci_err(&id, base);
            assert!(
                m.contains("must contain `.` or `:`, or be `localhost`"),
                "{base}: {m}"
            );
        }
        // `localhost` and a dotless host with a non-default port are hosts.
        let id = format!("localhost/oci/acme/mcp@{d}");
        assert_eq!(oci_ok(&id, "http://localhost"), id);
        let id = format!("artifact-keeper:8080/oci/acme/mcp@{d}");
        assert_eq!(oci_ok(&id, "http://artifact-keeper:8080"), id);
    }

    #[test]
    fn oci_spec_edge_references_never_change_the_source() {
        let d = oci_digest();
        // IPv6 origin: only the exact bracketed host and port is this AK.
        let base = "http://[::1]:8080";
        let id = format!("[::1]:8080/oci/acme/mcp@{d}");
        assert_eq!(oci_ok(&id, base), id);
        for other in [
            format!("[::1]/oci/acme/mcp@{d}"),
            format!("[::1]:8081/oci/acme/mcp@{d}"),
            format!("[::2]:8080/oci/acme/mcp@{d}"),
            format!("::1:8080/oci/acme/mcp@{d}"),
        ] {
            oci_err(&other, base);
        }
        // A written-out default port is dropped from the AK host, as it is
        // from the served identifier, so only the port-less form matches.
        let base = "https://ak.example.test:443";
        let id = format!("ak.example.test/oci/acme/mcp@{d}");
        assert_eq!(oci_ok(&id, base), id);
        assert!(
            oci_err(&format!("ak.example.test:443/oci/acme/mcp@{d}"), base)
                .contains("not this AK instance")
        );
        // `:latest` beside a digest is still pinned by the digest: AK serves a
        // resolved floating tag this way, and the engine runs the digest.
        let id = format!("ak.example.test/oci/acme/mcp:latest@{d}");
        assert_eq!(oci_ok(&id, AK), id);
        oci_err("ak.example.test/oci/acme/mcp:latest", AK);
        oci_err("ak.example.test/oci/acme/mcp:latest@", AK);
        // Homoglyphs in the host (Cyrillic `а`) or the path.
        assert!(
            oci_err(&format!("\u{430}k.example.test/oci/acme/mcp@{d}"), AK)
                .contains("not this AK instance")
        );
        oci_err(&format!("ak.example.test/oci/\u{430}cme/mcp@{d}"), AK);
        oci_err(&format!("ak.example.test/oci/acme/mcp:1\u{2024}0@{d}"), AK);
        // An identifier longer than 512 characters, even on this AK.
        let id = format!("ak.example.test/oci/{}/mcp@{d}", "a".repeat(480));
        assert!(id.len() > 512);
        oci_err(&id, AK);
        // SHA-512 is a valid OCI digest but not the pin AK serves.
        assert!(oci_err(
            &format!("ak.example.test/oci/acme/mcp@sha512:{}", "a".repeat(128)),
            AK
        )
        .contains("must be SHA-256"));
    }

    #[test]
    fn oci_spec_refuses_repository_keys_outside_the_image_path_grammar() {
        // AK repository keys may hold upper case or end in `_`/`.`/`-`; such a
        // key is not a valid image path component, and podman would refuse the
        // reference too, so the job fails as invalid rather than running.
        let d = oci_digest();
        for key in [
            "Docker_Local",
            "docker-local_",
            "docker-local.",
            "docker-local-",
        ] {
            let m = oci_err(&format!("ak.example.test/{key}/acme/mcp@{d}"), AK);
            assert!(m.contains("not a valid image name"), "{key}: {m}");
        }
        let id = format!("ak.example.test/docker_local/acme/mcp@{d}");
        assert_eq!(oci_ok(&id, AK), id);
    }

    #[test]
    fn oci_spec_keeps_guest_data_off_the_validated_source() {
        let digest = oci_digest();
        let tag_ref = format!("ak.example.test/oci-local/acme/mcp:1.0@{digest}");
        let spec = guest_spec(
            "j",
            &json!({"package": {"registryType": "oci", "identifier": tag_ref}}),
            AK,
            &Images::default(),
        )
        .unwrap();
        assert_eq!(spec.image, tag_ref);
        assert!(spec.argv.is_empty());

        let bare_ref = format!("ak.example.test/oci-local/acme/mcp@{digest}");
        let spec = guest_spec(
            "j",
            &json!({"package": {"registryType": "oci", "identifier": bare_ref}}),
            AK,
            &Images::default(),
        )
        .unwrap();
        assert_eq!(spec.image, bare_ref);

        // The matching non-default port is part of this AK origin.
        let port_ref = format!("ak.example.test:8443/oci/acme/mcp@{digest}");
        let spec = guest_spec(
            "j",
            &json!({"package": {"registryType": "oci", "identifier": port_ref}}),
            "https://ak.example.test:8443",
            &Images::default(),
        )
        .unwrap();
        assert_eq!(spec.image, port_ref);

        let canonical = format!("ak.example.test/oci/acme/mcp@{digest}");
        let target = json!({"package": {
            "registryType": "oci",
            "identifier": canonical.clone(),
            "packageArguments": [
                {"type": "named", "name": "--image", "value": "evil.test/x"},
                {"type": "named", "name": "--registry", "value": "https://evil.test"},
            ],
            "environmentVariables": [
                {"name": "DOCKER_HOST", "value": "tcp://evil.test:2375"},
                {"name": "IMAGE", "value": "evil.test/x"},
            ],
        }});
        let spec = guest_spec("j", &target, AK, &Images::default()).unwrap();
        assert_eq!(spec.image, canonical);
        assert_eq!(spec.network, "none");
        assert!(spec.argv.iter().any(|a| a == "evil.test/x"));
        let env: std::collections::HashMap<_, _> = spec.env.iter().cloned().collect();
        assert_eq!(env["DOCKER_HOST"], "tcp://evil.test:2375");

        // The package arguments are guest argv after the image, never engine
        // options before it.
        let plan = OciRunner::default().plan(&spec).unwrap();
        let image_at = plan.args.iter().position(|a| *a == canonical).unwrap();
        assert_eq!(
            plan.args
                .iter()
                .filter(|a| a.as_str() == canonical.as_str())
                .count(),
            1
        );
        assert!(plan.args[..image_at].iter().all(|a| a != "evil.test/x"));
        assert!(plan.args[image_at + 1..].iter().any(|a| a == "evil.test/x"));
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
            plan.cleanup[0],
            Cmd::new("podman", &["rm", "-f", &name]),
            "{:?}",
            plan.cleanup
        );
        assert!(!plan.cleanup.iter().any(|c| c.args[0] == "rmi"));
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
            "identifier": format!("ak.example.test/oci/acme/mcp@{}", oci_digest())}});
        let spec = guest_spec("j3", &t, AK, &Images::default()).unwrap();
        let plan = OciRunner::default().plan(&spec).unwrap();
        assert!(plan.args.iter().any(|a| a == "--network=none"));
        // The job's own image is pruned after the container is removed.
        assert_eq!(plan.cleanup.len(), 2);
        assert_eq!(plan.cleanup[1], Cmd::new("podman", &["rmi", &spec.image]));
        // No network is created for it, and none removed.
        assert!(plan.setup.is_empty());
        assert!(plan.host_lookup.is_none());
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
            runner_from_env(env(&[("AK_MCP_SANDBOX_COMMAND", "/x")]), "w")
                .unwrap()
                .name(),
            "external"
        );
        let r = runner_from_env(
            env(&[
                ("AK_MCP_SANDBOX_ENGINE", "docker"),
                ("AK_MCP_SANDBOX_RUNTIME", "kata-fc"),
            ]),
            "host-1",
        )
        .unwrap();
        assert_eq!(r.name(), "oci");
        let p = r.plan(&spec).unwrap();
        assert_eq!(p.program, "docker");
        assert!(p.args.iter().any(|a| a == "--runtime=kata-fc"));
        assert!(p
            .args
            .iter()
            .any(|a| a == "--label=com.artifactkeeper.mcp-sandbox.owner=host-1"));
        let p = runner_from_env(env(&[("AK_MCP_SANDBOX_GATEWAY", "fwd")]), "w")
            .unwrap()
            .plan(&spec)
            .unwrap();
        assert_eq!(p.setup[1].args.last().unwrap(), "fwd");
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

    fn network_arg(plan: &RunPlan) -> String {
        let nets: Vec<&str> = plan
            .args
            .iter()
            .filter_map(|a| a.strip_prefix("--network="))
            .collect();
        assert_eq!(nets.len(), 1, "exactly one --network: {:?}", plan.args);
        nets[0].to_string()
    }

    fn pypi_target() -> Value {
        json!({"package": {"registryType": "pypi", "identifier": "acme-mcp", "version": "2.0",
            "registryBaseUrl": "https://ak.example.test/pypi/pypi-remote"}})
    }

    /// #5447: every npm and PyPI guest gets an internal network of its own
    /// that only the forwarder joins, created before the guest starts and
    /// removed after it; never a network another guest shares.
    #[test]
    fn npm_and_pypi_guests_get_a_network_of_their_own() {
        for target in [npm_target(), pypi_target()] {
            let spec = guest_spec("j1", &target, AK, &Images::default()).unwrap();
            let r = OciRunner::default();
            let plan = r.plan(&spec).unwrap();
            let name = plan
                .args
                .iter()
                .find_map(|a| a.strip_prefix("--name="))
                .unwrap()
                .to_string();
            let net = network_arg(&plan);
            assert_eq!(net, name, "the guest's network is its own");
            assert_ne!(net, "ak-mcp-sandbox");
            assert_eq!(
                plan.setup,
                [
                    Cmd::new(
                        "podman",
                        &[
                            "network",
                            "create",
                            "--internal",
                            "--label=com.artifactkeeper.mcp-sandbox=j1",
                            "--label=com.artifactkeeper.mcp-sandbox.owner=ak-mcp-introspector",
                            &net,
                        ]
                    ),
                    Cmd::new(
                        "podman",
                        &[
                            "network",
                            "connect",
                            "--alias",
                            "ak.example.test",
                            &net,
                            "ak-gateway"
                        ]
                    ),
                ]
            );
            // The guest gets the forwarder's address on its network as a
            // hosts entry (no dependence on the engine's DNS).
            let fmt = format!("{{{{(index .NetworkSettings.Networks \"{net}\").IPAddress}}}}");
            assert_eq!(
                plan.host_lookup,
                Some(HostLookup {
                    host: "ak.example.test".into(),
                    cmd: Cmd::new(
                        "podman",
                        &["container", "inspect", "--format", &fmt, "ak-gateway"]
                    ),
                })
            );
            // Removed after the guest, the forwarder detached first (never
            // `network rm -f`, which would remove the forwarder too).
            assert_eq!(
                plan.cleanup,
                [
                    Cmd::new("podman", &["rm", "-f", &name]),
                    Cmd::new(
                        "podman",
                        &["network", "disconnect", "-f", &net, "ak-gateway"]
                    ),
                    Cmd::new("podman", &["network", "rm", &net]),
                ]
            );
            assert!(!plan.cleanup.iter().any(|c| c.args.contains(&"-f".into())
                && c.args.first().map(String::as_str) == Some("network")
                && c.args.get(1).map(String::as_str) == Some("rm")));
            // Two guests of the same job never share one.
            let other = network_arg(&r.plan(&spec).unwrap());
            assert_ne!(other, net);
        }
        // The forwarder's name and the engine are configurable; the AK
        // hostname alias carries no port.
        let spec = guest_spec(
            "j9",
            &json!({"package": {"registryType": "npm", "identifier": "x", "version": "1.0.0",
                "registryBaseUrl": "https://ak.example.test:8443/npm/r"}}),
            "https://ak.example.test:8443",
            &Images::default(),
        )
        .unwrap();
        let plan = OciRunner {
            engine: "docker".into(),
            runtime: "kata-fc".into(),
            gateway: "fwd-1".into(),
            ..Default::default()
        }
        .plan(&spec)
        .unwrap();
        let net = network_arg(&plan);
        assert_eq!(plan.setup[0].program, "docker");
        assert_eq!(
            plan.setup[1].args,
            [
                "network",
                "connect",
                "--alias",
                "ak.example.test",
                &net,
                "fwd-1"
            ]
        );
        assert_eq!(
            plan.cleanup[1].args,
            ["network", "disconnect", "-f", &net, "fwd-1"]
        );
    }

    /// #5447: a configuration that cannot isolate guests is no runner at
    /// all, so the worker does not start (and claims nothing) instead of
    /// failing every job it claims.
    #[test]
    fn a_configuration_that_cannot_isolate_guests_is_no_runner() {
        let get = |pairs: Vec<(&'static str, &'static str)>| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let Err(m) = runner_from_env(get(vec![("AK_MCP_SANDBOX_NETWORK", "ak-mcp-sandbox")]), "w")
        else {
            panic!("a shared guest network must be refused");
        };
        assert!(m.contains("AK_MCP_SANDBOX_NETWORK=ak-mcp-sandbox"), "{m}");
        assert!(m.contains("#5447"), "{m}");
        let Err(m) = runner_from_env(get(vec![("AK_MCP_SANDBOX_GATEWAY", "")]), "w") else {
            panic!("an empty gateway must be refused");
        };
        assert!(m.contains("AK_MCP_SANDBOX_GATEWAY"), "{m}");
        // Set but empty is the same as unset; an external launcher has no
        // use for either.
        assert!(runner_from_env(get(vec![("AK_MCP_SANDBOX_NETWORK", "")]), "w").is_ok());
        assert!(runner_from_env(
            get(vec![
                ("AK_MCP_SANDBOX_COMMAND", "/opt/launch"),
                ("AK_MCP_SANDBOX_NETWORK", "x")
            ]),
            "w"
        )
        .is_ok());
    }

    /// What `plan` cannot run for the deployment's sake (no forwarder, an
    /// AK base URL the forwarder cannot stand in for) is a deployment
    /// error, which the worker reports as retryable `start_failed`.
    #[test]
    fn configurations_that_cannot_isolate_guests_are_refused() {
        let npm = guest_spec("j1", &npm_target(), AK, &Images::default()).unwrap();
        let oci = guest_spec(
            "j3",
            &json!({"package": {"registryType": "oci",
                "identifier": format!("ak.example.test/oci/acme/mcp@{}", oci_digest())}}),
            AK,
            &Images::default(),
        )
        .unwrap();
        // No forwarder: npm/PyPI refused, OCI (no network) still runs.
        let no_gw = OciRunner {
            gateway: " ".into(),
            ..Default::default()
        };
        assert!(
            matches!(no_gw.plan(&npm), Err(SandboxError::Deployment(m)) if m.contains("AK_MCP_SANDBOX_GATEWAY"))
        );
        assert_eq!(network_arg(&no_gw.plan(&oci).unwrap()), "none");
        // An AK URL that is an IP address: the guest would bypass the
        // forwarder's alias, and an internal network has no route to it.
        let mut by_ip = npm.clone();
        by_ip.ak_base_url = "https://203.0.113.10".into();
        assert!(matches!(
            OciRunner::default().plan(&by_ip),
            Err(SandboxError::Deployment(_))
        ));
    }

    #[test]
    fn the_forwarder_alias_is_the_ak_host_name() {
        assert_eq!(
            gateway_alias("https://ak.example.com").unwrap(),
            "ak.example.com"
        );
        assert_eq!(
            gateway_alias("https://ak.example.com:8443/base/").unwrap(),
            "ak.example.com"
        );
        for ip in ["https://203.0.113.10", "http://[2001:db8::1]:8080"] {
            assert!(
                matches!(gateway_alias(ip), Err(SandboxError::Deployment(_))),
                "{ip}"
            );
        }
        for bad in ["not a url", "unix:/run/ak.sock"] {
            assert!(
                matches!(gateway_alias(bad), Err(SandboxError::Invalid(_))),
                "{bad}"
            );
        }
    }

    /// The guest's network not being created, or the forwarder not joining
    /// it, aborts the run before the guest starts: `start_failed` with the
    /// engine's message, and the cleanup still runs.
    #[tokio::test]
    async fn a_guest_never_starts_without_its_network() {
        let dir = scratch();
        let started = dir.join("started");
        let cleaned = dir.join("cleaned");
        let mut plan = sh(&format!("touch {}; exit 0", started.display()));
        plan.cleanup = vec![Cmd::new(
            "sh",
            &["-c", &format!("touch {}", cleaned.display())],
        )];
        for failing in [
            vec![Cmd::new(
                "sh",
                &["-c", "echo 'Error: network already exists' >&2; exit 125"],
            )],
            vec![
                Cmd::new("true", &[]),
                Cmd::new(
                    "sh",
                    &[
                        "-c",
                        "echo 'Error: no container with name ak-gateway' >&2; exit 125",
                    ],
                ),
            ],
            vec![Cmd::new("/nonexistent/podman", &["network", "create"])],
        ] {
            plan.setup = failing;
            let r = run_and_probe(&plan, 10, 1024).await;
            assert_eq!(r.outcome, "start_failed", "{r:?}");
            let e = r.error.unwrap();
            assert!(e.contains("guest was not started"), "{e}");
            assert!(!started.exists(), "the guest ran without its network");
            assert!(cleaned.exists(), "cleanup ran");
            std::fs::remove_file(&cleaned).unwrap();
        }
        let r = run_and_probe(&plan, 10, 1024).await;
        assert!(r
            .error
            .unwrap()
            .contains("/nonexistent/podman network create"));
        // Every setup command succeeding: the guest runs.
        plan.setup = vec![Cmd::new("true", &[]), Cmd::new("true", &[])];
        assert_eq!(run_and_probe(&plan, 10, 1024).await.outcome, "needs_config");
        assert!(started.exists());
        // The stderr kept for the error names the cause.
        plan.setup = vec![Cmd::new(
            "sh",
            &["-c", "echo 'Error: network already exists' >&2; exit 125"],
        )];
        let e = run_and_probe(&plan, 10, 1024).await.error.unwrap();
        assert!(e.contains("network already exists"), "{e}");
    }

    #[test]
    fn host_entries_and_lookup_output() {
        let args: Vec<String> = ["run", "--rm", "img"].map(String::from).to_vec();
        assert_eq!(
            with_host_entry(&args, "ak.example.test", "10.89.7.3"),
            ["run", "--add-host=ak.example.test:10.89.7.3", "--rm", "img"]
        );
        assert_eq!(parse_lookup_ip("10.89.7.3\n").unwrap(), "10.89.7.3");
        assert_eq!(parse_lookup_ip(" fd00::3 ").unwrap(), "fd00::3");
        // What Docker and Podman print for a network the container is not on.
        for bad in ["", "<no value>", "0.0.0.0", "ak-gateway"] {
            assert!(parse_lookup_ip(bad).is_err(), "{bad:?}");
        }
    }

    /// The forwarder's address is read after setup and handed to the guest
    /// as `--add-host`; when it cannot be read the guest never starts.
    #[tokio::test]
    async fn the_guest_gets_the_forwarders_address_or_does_not_start() {
        let dir = scratch();
        let argv = dir.join("argv");
        let engine = dir.join("engine");
        std::fs::write(
            &engine,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
                argv.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
        let lookup = |script: &str| HostLookup {
            host: "ak.example.test".into(),
            cmd: Cmd::new("sh", &["-c", script]),
        };
        let mut plan = RunPlan {
            setup: vec![Cmd::new("true", &[])],
            host_lookup: Some(lookup("echo 10.89.7.3")),
            program: engine.to_string_lossy().into_owned(),
            args: ["run", "--rm", "img"].map(String::from).to_vec(),
            cleanup: Vec::new(),
        };
        run_and_probe(&plan, 10, 1024).await;
        assert_eq!(
            std::fs::read_to_string(&argv).unwrap(),
            "run\n--add-host=ak.example.test:10.89.7.3\n--rm\nimg\n"
        );
        for failing in [
            "echo '<no value>'",
            "echo 'Error: no such container ak-gateway' >&2; exit 125",
        ] {
            std::fs::remove_file(&argv).ok();
            plan.host_lookup = Some(lookup(failing));
            let r = run_and_probe(&plan, 10, 1024).await;
            assert_eq!(r.outcome, "start_failed", "{r:?}");
            assert!(
                r.error.unwrap().contains("forwarder's address"),
                "{failing}"
            );
            assert!(!argv.exists(), "the guest started without the address");
        }
    }

    fn sh(script: &str) -> RunPlan {
        RunPlan {
            program: "sh".into(),
            args: vec!["-c".into(), script.into()],
            ..Default::default()
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
                "#!/bin/sh\necho \"$*\" >> {}\ncase \"$1 $2\" in ps*) printf 'c1\\nc2\\n';; 'network ls') printf 'n1\\n';; esac\n",
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
            "ps -a -q --filter label=com.artifactkeeper.mcp-sandbox.owner=host-1\n\
             rm -f c1 c2\n\
             network ls -q --filter label=com.artifactkeeper.mcp-sandbox.owner=host-1\n\
             network disconnect -f n1 ak-gateway\n\
             network rm n1\n"
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
