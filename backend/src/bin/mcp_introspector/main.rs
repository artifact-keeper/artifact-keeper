//! `ak-mcp-introspector`: the isolated MCP introspection worker (#5253).
//!
//! It is deliberately a separate binary: the backend server process never
//! connects to an MCP server, never starts one, and does not link this code.
//! The worker claims jobs from the backend's HTTP API with an API token
//! carrying the `mcp:introspect` scope, probes remotes (public ranges only,
//! no redirects, 1 MiB cap, never `tools/call`, never a publisher header) or
//! runs stdio packages in a sandbox, and posts each result back.
//!
//! Subcommands:
//!
//! * `run` — the job loop (`AK_URL`, `AK_MCP_INTROSPECTOR_TOKEN`;
//!   `--sandbox` to also take `sandbox_run` jobs);
//! * `probe <url>` — probe one remote and print the result (no backend);
//! * `convert --from <inventory> <file>` — a Docker MCP Gateway / ToolHive
//!   / static inventory as a capability report body;
//! * `push --from <inventory> --repo --server --version <file>` — convert
//!   and post it (`AK_URL`, `AK_TOKEN` with `write:artifacts`);
//! * `render-sandbox <job.json>` — print the guest spec and the runner
//!   command a claimed sandbox job would use, without running it.
//!
//! Deployment: `docs/mcp-registry.md`, "Capabilities and introspection".

mod adapters;
mod http;
mod protocol;
mod sandbox;
mod stdio;
mod worker;

use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

#[derive(Parser, Debug)]
#[command(
    name = "ak-mcp-introspector",
    version,
    about = "Artifact Keeper MCP introspection worker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Claim and run introspection jobs.
    Run {
        #[arg(long, env = "AK_URL")]
        ak_url: String,
        #[arg(long, env = "AK_MCP_INTROSPECTOR_TOKEN", hide_env_values = true)]
        token: String,
        #[arg(
            long,
            env = "AK_MCP_INTROSPECTOR_ID",
            default_value = "ak-mcp-introspector"
        )]
        worker_id: String,
        /// Also run `sandbox_run` jobs (configure the runner with
        /// `AK_MCP_SANDBOX_*`).
        #[arg(long, env = "AK_MCP_INTROSPECTOR_SANDBOX")]
        sandbox: bool,
        #[arg(long, default_value_t = 30)]
        poll_secs: u64,
        /// Run at most one job and exit.
        #[arg(long)]
        once: bool,
    },
    /// Probe one remote URL and print the result.
    Probe { url: String },
    /// Convert an inventory into a capability report body.
    Convert {
        #[arg(long)]
        from: String,
        file: String,
    },
    /// Convert an inventory and post it to a server version.
    Push {
        #[arg(long)]
        from: String,
        #[arg(long, env = "AK_URL")]
        ak_url: String,
        #[arg(long, env = "AK_TOKEN", hide_env_values = true)]
        token: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        version: String,
        file: String,
    },
    /// Print what a claimed sandbox job would run.
    RenderSandbox { job: String },
    /// Run a sandbox job document (as `render-sandbox` takes it) for real,
    /// with the configured runner, and print the probe result. No backend:
    /// a deployment check for the sandbox (runtime, network, images).
    SandboxProbe { job: String },
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// Refuse to probe with an override that would admit private addresses.
fn ensure_public_only() -> Result<(), String> {
    match http::private_override_set(env) {
        Some(k) => Err(format!(
            "{k} is set: the introspector only probes public addresses; unset it for this process"
        )),
        None => Ok(()),
    }
}

fn read_json(file: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{file}: {e}"))
}

fn convert_file(from: &str, file: &str) -> Result<Value, String> {
    let kind = adapters::Inventory::parse(from).ok_or_else(|| {
        format!("unknown inventory `{from}` (docker-gateway, docker-catalog, toolhive, static)")
    })?;
    adapters::convert(kind, &read_json(file)?)
}

/// The guest spec and runner command for a claimed job document.
fn render_sandbox(job: &Value) -> Result<Value, String> {
    let runner = sandbox::runner_from_env(env);
    let ak = job["akBaseUrl"].as_str().ok_or("job has no akBaseUrl")?;
    let spec = sandbox::guest_spec(
        job["jobId"].as_str().unwrap_or("job"),
        &job["target"],
        ak,
        &sandbox::images_from_env(env),
    )
    .map_err(|e| e.to_string())?;
    let plan = runner.plan(&spec).map_err(|e| e.to_string())?;
    let mut command = vec![plan.program];
    command.extend(plan.args);
    Ok(json!({"runner": runner.name(), "spec": spec, "command": command}))
}

async fn dispatch(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Run {
            ak_url,
            token,
            worker_id,
            sandbox,
            poll_secs,
            once,
        } => {
            ensure_public_only()?;
            let w = worker::Worker {
                backend: worker::Backend::new(&ak_url, &token),
                worker_id,
                runner: sandbox.then(|| sandbox::runner_from_env(env)),
                images: sandbox::images_from_env(env),
                http: http::guarded_client(),
            };
            tracing::info!(kinds = ?w.kinds(), "ak-mcp-introspector started");
            if once {
                w.once().await.map(|_| ())
            } else {
                w.run_forever(Duration::from_secs(poll_secs.max(1))).await;
                Ok(())
            }
        }
        Command::Probe { url } => {
            ensure_public_only()?;
            let r = worker::probe_remote(http::guarded_client(), &url).await;
            println!(
                "{}",
                serde_json::to_string_pretty(&r.to_result_json()).unwrap_or_default()
            );
            Ok(())
        }
        Command::Convert { from, file } => {
            let body = convert_file(&from, &file)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&body).unwrap_or_default()
            );
            Ok(())
        }
        Command::Push {
            from,
            ak_url,
            token,
            repo,
            server,
            version,
            file,
        } => {
            let body = convert_file(&from, &file)?;
            let resp = worker::Backend::new(&ak_url, &token)
                .push(&repo, &server, &version, &body)
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            );
            Ok(())
        }
        Command::RenderSandbox { job } => {
            let out = render_sandbox(&read_json(&job)?)?;
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            Ok(())
        }
        Command::SandboxProbe { job } => {
            let out = sandbox_probe_job(sandbox::runner_from_env(env).as_ref(), &read_json(&job)?)
                .await?;
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            if out["outcome"] == "ok" {
                Ok(())
            } else {
                Err(format!("sandbox probe outcome: {}", out["outcome"]))
            }
        }
    }
}

/// The result body of running the sandbox job document `job` with `runner`.
async fn sandbox_probe_job(
    runner: &dyn sandbox::SandboxRunner,
    job: &Value,
) -> Result<Value, String> {
    let ak = job["akBaseUrl"].as_str().ok_or("job has no akBaseUrl")?;
    let report = worker::sandbox_probe(
        runner,
        &sandbox::images_from_env(env),
        job["jobId"].as_str().unwrap_or("job"),
        &job["target"],
        ak,
    )
    .await;
    Ok(report.to_result_json())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = dispatch(Cli::parse()).await {
        eprintln!("ak-mcp-introspector: {e}");
        std::process::exit(1);
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ak-intro-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    /// `sandbox-probe` runs the guest the runner plans and probes it over
    /// stdio: here an external runner whose "guest" is the shell MCP server
    /// the `mcp-sandbox` workflow also runs under gVisor. A target the
    /// sandbox refuses starts nothing.
    #[tokio::test]
    async fn sandbox_probe_runs_a_guest_over_stdio() {
        let runner = sandbox::ExternalRunner {
            command: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/mcp_sandbox/echo-mcp-server.sh"
            )
            .into(),
        };
        let job = |identifier: &str| {
            json!({"jobId": "j", "akBaseUrl": "https://ak.test", "target": {"package": {
                "registryType": "oci", "identifier": identifier,
                "transport": {"type": "stdio"}}}})
        };
        let digest = format!("sha256:{}", "a".repeat(64));
        let out = sandbox_probe_job(&runner, &job(&format!("ak.test/mcp/echo@{digest}")))
            .await
            .unwrap();
        assert_eq!(out["outcome"], "ok", "{out}");
        assert_eq!(out["tools"][0]["name"], "echo", "{out}");
        assert_eq!(out["details"]["runner"], "external");
        let out = sandbox_probe_job(&runner, &job(&format!("evil.test/x@{digest}")))
            .await
            .unwrap();
        assert_eq!(out["outcome"], "unsupported", "{out}");
        assert!(sandbox_probe_job(&runner, &json!({})).await.is_err());
        let c = Cli::try_parse_from(["x", "sandbox-probe", "j.json"]).unwrap();
        assert!(matches!(c.command, Command::SandboxProbe { .. }));
    }

    #[test]
    fn cli_parses() {
        let c = Cli::try_parse_from(["x", "convert", "--from", "toolhive", "f.json"]).unwrap();
        assert!(matches!(c.command, Command::Convert { .. }));
        let c = Cli::try_parse_from([
            "x",
            "run",
            "--ak-url",
            "http://ak",
            "--token",
            "t",
            "--once",
            "--sandbox",
        ])
        .unwrap();
        assert!(matches!(
            c.command,
            Command::Run {
                once: true,
                sandbox: true,
                ..
            }
        ));
        assert!(Cli::try_parse_from(["x", "bogus"]).is_err());
    }

    #[tokio::test]
    async fn convert_render_and_errors() {
        let f = tmp("inv.json", r#"{"tools": ["a", "b"]}"#);
        assert_eq!(
            convert_file("toolhive", &f).unwrap()["tools"][1]["name"],
            "b"
        );
        assert!(convert_file("nope", &f).is_err());
        assert!(convert_file("toolhive", "/nonexistent.json").is_err());
        let bad = tmp("bad.json", "{");
        assert!(read_json(&bad).is_err());
        let job = json!({"jobId": "j", "akBaseUrl": "https://ak.test", "target": {"package": {
            "registryType": "npm", "identifier": "x", "version": "1", "registryBaseUrl": "https://ak.test/npm/r"}}});
        let out = render_sandbox(&job).unwrap();
        assert!(out["command"][0].as_str().is_some());
        assert_eq!(out["spec"]["network"], "ak-only");
        assert!(render_sandbox(&json!({})).is_err());
        let jf = tmp("job.json", &job.to_string());
        let c = Cli::try_parse_from(["x", "render-sandbox", jf.as_str()]).unwrap();
        assert!(dispatch(c).await.is_ok());
        let c = Cli::try_parse_from(["x", "convert", "--from", "toolhive", f.as_str()]).unwrap();
        assert!(dispatch(c).await.is_ok());
        let c = Cli::try_parse_from([
            "x",
            "push",
            "--from",
            "toolhive",
            "--ak-url",
            "http://127.0.0.1:9",
            "--token",
            "t",
            "--repo",
            "r",
            "--server",
            "com.acme/x",
            "--version",
            "1",
            f.as_str(),
        ])
        .unwrap();
        assert!(dispatch(c).await.is_err(), "unreachable backend");
        let c = Cli::try_parse_from(["x", "probe", "http://127.0.0.1/mcp"]).unwrap();
        assert!(
            dispatch(c).await.is_ok(),
            "a refused target is a printed result"
        );
        let c = Cli::try_parse_from([
            "x",
            "run",
            "--ak-url",
            "http://127.0.0.1:9",
            "--token",
            "t",
            "--once",
        ])
        .unwrap();
        assert!(dispatch(c).await.is_err());
        assert!(ensure_public_only().is_ok() || env("AK_SSRF_ALLOW_PRIVATE_CIDRS").is_some());
    }
}
