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
//! * 120 s wall clock, enforced by the worker around the whole run.
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

/// Runner images (the operator should mirror them through AK too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Images {
    pub node: String,
    pub python: String,
}

impl Default for Images {
    fn default() -> Self {
        Self {
            node: "docker.io/library/node:22-alpine".into(),
            python: "ghcr.io/astral-sh/uv:python3.12-alpine".into(),
        }
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
    })
}

/// A process to start: its stdin/stdout are the guest's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub program: String,
    pub args: Vec<String>,
}

/// The pluggable sandbox interface. A runner renders a [`GuestSpec`] into
/// the command that starts the throwaway guest; the worker spawns it, speaks
/// MCP over its stdio, and kills it after the wall clock.
pub trait SandboxRunner: Send + Sync {
    fn name(&self) -> &str;
    fn plan(&self, spec: &GuestSpec) -> Result<RunPlan, SandboxError>;
}

/// docker/podman with an OCI runtime (gVisor `runsc` by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRunner {
    /// `podman`, `docker`, or a path (`AK_MCP_SANDBOX_ENGINE`).
    pub engine: String,
    /// `runsc` (default), `kata-fc`, ...; empty = the engine's default
    /// (`AK_MCP_SANDBOX_RUNTIME`; refused unless `allow_default_runtime`).
    pub runtime: String,
    /// The pre-created network that reaches only AK (`AK_MCP_SANDBOX_NETWORK`).
    pub ak_network: String,
    pub memory: String,
    pub cpus: String,
    pub pids_limit: u32,
    pub tmpfs_size: String,
    pub allow_default_runtime: bool,
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
        }
    }
}

impl SandboxRunner for OciRunner {
    fn name(&self) -> &str {
        "oci"
    }

    fn plan(&self, spec: &GuestSpec) -> Result<RunPlan, SandboxError> {
        if self.runtime.is_empty() && !self.allow_default_runtime {
            return Err(SandboxError::Unsupported(
                "no sandbox runtime configured (AK_MCP_SANDBOX_RUNTIME, e.g. runsc); a plain \
                 container is not an isolation boundary for attacker-chosen install scripts"
                    .into(),
            ));
        }
        let network = match spec.network.as_str() {
            "none" => "none".to_string(),
            _ => self.ak_network.clone(),
        };
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "-i".into(),
            format!("--name=ak-mcp-sbx-{}", spec.job_id),
            format!("--label=com.artifactkeeper.mcp-sandbox={}", spec.job_id),
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
            "--workdir=/tmp".into(),
        ]);
        for (k, v) in &spec.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        args.push(spec.image.clone());
        args.extend(spec.argv.iter().cloned());
        Ok(RunPlan {
            program: self.engine.clone(),
            args,
        })
    }
}

/// An operator-supplied launcher (microVM, Kubernetes job, ...): started as
/// `<command> <spec JSON>`; its stdin/stdout must be the guest's.
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
        })
    }
}

/// The runner the environment configures: `AK_MCP_SANDBOX_COMMAND` selects
/// an [`ExternalRunner`], otherwise an [`OciRunner`] from
/// `AK_MCP_SANDBOX_ENGINE` / `_RUNTIME` / `_NETWORK` / `_MEMORY` / `_CPUS`.
pub fn runner_from_env(get: impl Fn(&str) -> Option<String>) -> Box<dyn SandboxRunner> {
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

/// Run a plan and probe the guest over its stdio, bounded by the wall
/// clock. The guest is killed when the probe ends, whatever the outcome.
pub async fn run_and_probe(
    plan: &RunPlan,
    max_items: usize,
    max_bytes: usize,
) -> crate::protocol::ProbeReport {
    use crate::protocol::ProbeReport;
    let mut child = match tokio::process::Command::new(&plan.program)
        .args(&plan.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
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
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill().await;
        return ProbeReport {
            outcome: "start_failed".into(),
            auth_state: "none".into(),
            error: Some("sandbox stdio unavailable".into()),
            ..Default::default()
        };
    };
    // Installs on first run are slow: one message may take most of the
    // wall clock, the whole run may not exceed it.
    let mut t = crate::stdio::StdioTransport::new(stdout, stdin, WALL_CLOCK, max_bytes);
    let report =
        match tokio::time::timeout(WALL_CLOCK, crate::protocol::probe(&mut t, max_items)).await {
            Ok(mut r) => {
                if r.outcome == "start_failed" {
                    // The guest exited before answering: typically a server that
                    // refuses to start without configuration.
                    r.outcome = "needs_config".into();
                }
                r
            }
            Err(_) => ProbeReport {
                outcome: "timeout".into(),
                auth_state: "none".into(),
                error: Some("sandbox wall clock (120 s) exceeded".into()),
                ..Default::default()
            },
        };
    drop(t);
    let _ = child.kill().await;
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
        // An OCI guest gets no network at all.
        let t = json!({"package": {"registryType": "oci",
            "identifier": "ak.example.test/oci/acme/mcp@sha256:abc"}});
        let spec = guest_spec("j3", &t, AK, &Images::default()).unwrap();
        let plan = OciRunner::default().plan(&spec).unwrap();
        assert!(plan.args.iter().any(|a| a == "--network=none"));
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
            runner_from_env(env(&[("AK_MCP_SANDBOX_COMMAND", "/x")])).name(),
            "external"
        );
        let r = runner_from_env(env(&[
            ("AK_MCP_SANDBOX_ENGINE", "docker"),
            ("AK_MCP_SANDBOX_RUNTIME", "kata-fc"),
        ]));
        assert_eq!(r.name(), "oci");
        let p = r.plan(&spec).unwrap();
        assert_eq!(p.program, "docker");
        assert!(p.args.iter().any(|a| a == "--runtime=kata-fc"));
        assert_eq!(
            images_from_env(env(&[("AK_MCP_SANDBOX_NODE_IMAGE", "ak/node")])).node,
            "ak/node"
        );
        assert_eq!(placeholder(""), "AK_PLACEHOLDER_VALUE");
        assert!(SandboxError::Invalid("x".into()).to_string() == "x");
    }

    #[tokio::test]
    async fn run_and_probe_reports_start_failures() {
        let plan = RunPlan {
            program: "/nonexistent/ak-sandbox".into(),
            args: vec![],
        };
        assert_eq!(run_and_probe(&plan, 10, 1024).await.outcome, "start_failed");
        // A guest that exits at once: the server would not start unconfigured.
        let plan = RunPlan {
            program: "true".into(),
            args: vec![],
        };
        assert_eq!(run_and_probe(&plan, 10, 1024).await.outcome, "needs_config");
    }
}
