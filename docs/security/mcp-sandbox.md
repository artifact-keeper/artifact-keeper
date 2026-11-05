# MCP sandbox introspection: reference deployment

Issue #5253. `ak-mcp-introspector run --sandbox` installs and starts an MCP
server package (npm, PyPI, or an OCI image) that a publisher chose, and asks
it for its tools over stdio. The install scripts and the server are
attacker-controlled code. This page describes a deployment where that code
runs in a gVisor (or microVM) guest that can reach only Artifact Keeper, and
where the worker that starts it holds nothing worth stealing.

The files are in [`deploy/mcp-introspector/`](../../deploy/mcp-introspector/).
What the worker does per job (the guest spec, the dropped arguments and
variables, the 120 s wall clock) is in
[`docs/mcp-registry.md`](../mcp-registry.md#the-ak-mcp-introspector-worker).

## Threat model

| Asset | Exposure | Control |
| --- | --- | --- |
| The sandbox host kernel | A guest runs arbitrary code (`npm install` scripts, the server). | gVisor `runsc` (user-space kernel) or a microVM runtime (`kata-fc`); a plain runc container is refused unless `AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME=true`. Read-only root, `/tmp` tmpfs, uid 65532, `--cap-drop=ALL`, `no-new-privileges`, pids/memory/CPU limits. |
| The container engine | Whoever drives the engine can start privileged containers. A rootful Docker or Podman socket is root on the host. | The worker drives **rootless** Podman as a dedicated user, on a host or VM used for nothing else. No socket is mounted into any container. On Kubernetes the worker has no engine at all: it creates guest pods through the API, limited by RBAC to one namespace. |
| The internal network, cloud metadata | A guest that can open connections can scan and pivot. | npm and PyPI guests join `ak-mcp-sandbox`, an internal network with no route out. Its only member is a TCP forwarder that answers on the AK hostname and forwards to AK. OCI guests run with `--network=none`. |
| Artifact Keeper credentials | The worker holds an `mcp:introspect` token. | The token can only claim jobs and post results. Guests never see it: the worker passes them only placeholder secrets (`AK_PLACEHOLDER_<NAME>`). Guests install anonymously, so map public, read-only repositories for packages that should be introspected. |
| Other jobs | A guest could persist between jobs. | `--rm`, a fresh name per job, jobs run one at a time, and the guest is killed at the wall clock. |

What this deployment does not cover: a guest can still talk to the AK
instance it installs from (it needs to), and gVisor reduces but does not
remove kernel attack surface. A microVM runtime is the stronger choice where
the host supports nested virtualisation.

## Option A: a dedicated host with rootless Podman (recommended)

1. **Host.** A VM or machine used only for the worker. Install Podman (4.4
   or later), gVisor (`runsc`, from <https://gvisor.dev/docs/user_guide/install/>),
   `podman-compose` or the Docker Compose plugin, and the
   `ak-mcp-introspector` binary (`cargo build --release --bin
   ak-mcp-introspector`).
2. **User.** Create `ak-sbx` with subuids and subgids, enable lingering
   (`loginctl enable-linger ak-sbx`), and register gVisor for that user's
   Podman in `~ak-sbx/.config/containers/containers.conf`:

   ```toml
   [engine.runtimes]
   runsc = ["/usr/local/bin/runsc"]
   ```

   Rootless gVisor needs `runsc --ignore-cgroups` on hosts without delegated
   cgroups v2. Check with `podman --runtime=runsc run --rm alpine dmesg`; the
   first line names gVisor.
3. **Network.** As `ak-sbx`, edit `AK_HOST` in
   `deploy/mcp-introspector/compose.sandbox-network.yaml` and
   `nginx-ak-gateway.conf`, then run `podman-compose -f
   compose.sandbox-network.yaml up -d`. This creates the internal network
   `ak-mcp-sandbox` and the forwarder `ak-gateway`. The forwarder joins
   that network under the AK hostname as an alias and forwards TCP 443 (and
   80) to the real AK. TLS stays end to end and the certificate stays AK's.
4. **Images.** Mirror the guest images (`AK_MCP_SANDBOX_NODE_IMAGE`,
   `AK_MCP_SANDBOX_PYTHON_IMAGE`) through an AK OCI repository, pin them by
   digest, and pull them once as `ak-sbx`. Guests run with `--pull=missing`.
5. **Service.** Install `systemd/ak-mcp-introspector.service` and
   `systemd/ak-mcp-introspector.env.example` (as
   `/etc/ak-mcp-introspector.env`, mode 0600, the `mcp:introspect` token in
   it). The unit runs as `ak-sbx` with `AK_MCP_SANDBOX_ENGINE=podman`,
   `AK_MCP_SANDBOX_RUNTIME=runsc` and `AK_MCP_SANDBOX_NETWORK=ak-mcp-sandbox`.
6. **Egress of the worker itself** (remote probes). Allow the AK host and
   public addresses only: drop RFC 1918, CGNAT, link-local (cloud metadata),
   loopback and the IPv6 equivalents at the host firewall. The worker's own
   address checks are a second layer.
7. **Check before enabling.** Run a real sandboxed probe with no backend:

   ```sh
   sudo -u ak-sbx env AK_MCP_SANDBOX_RUNTIME=runsc \
     ak-mcp-introspector sandbox-probe deploy/mcp-introspector/sandbox-check/job.example.json
   ```

   It exits `0` only when the guest answered (`"outcome": "ok"`). Then set
   `mcp_sandbox_introspection: on` on the repositories that should use it.

## Option B: Kubernetes with a gVisor RuntimeClass

The worker uses the external runner
(`AK_MCP_SANDBOX_COMMAND=/opt/ak/k8s-launcher.sh`). For each job the launcher
creates one guest pod in the `ak-mcp-sandbox` namespace with
`runtimeClassName: gvisor`, attaches to its stdio, and deletes it. No engine
socket exists anywhere. The manifests are in `deploy/mcp-introspector/k8s/`:

| File | What it does |
| --- | --- |
| `namespace.yaml` | `ak-mcp-introspector` (the worker) and `ak-mcp-sandbox` (guests), with Pod Security `restricted`. |
| `runtimeclass-gvisor.yaml` | `RuntimeClass gvisor` (handler `runsc`). The nodes need gVisor's containerd shim; GKE Sandbox provides it as `gvisor`. |
| `rbac.yaml` | A service account that may create, get, delete and attach to pods in `ak-mcp-sandbox`, and nothing else. |
| `networkpolicy.yaml` | Guests: no ingress, egress only to the AK service (and DNS). Worker: egress to the API server, AK and public addresses, never to private ranges or metadata. |
| `launcher-configmap.yaml` | `k8s-launcher.sh`: guest spec JSON in, `kubectl run --attach` with the restricted security context, runtime class and wall clock out. |
| `deployment.yaml` | One worker replica (jobs run one at a time per worker), token from a Secret, the launcher mounted. Build the image from the binary and `kubectl`. |

The launcher labels each guest pod `ak-mcp-sandbox/network: ak-only` (npm,
PyPI) or `none` (OCI). The default-deny policy blocks all traffic, and only
`ak-only` pods get egress to AK and DNS. Edit the placeholder addresses in
`networkpolicy.yaml` first: the AK ingress and the API server. The policies
are IPv4 only, so on a dual-stack cluster add the IPv6 ranges as well.

To check the deployment, mount `sandbox-check/job.example.json` as
`/opt/ak/job.json` (see `deployment.yaml`), edit it for an image you pushed,
and run:

```sh
kubectl -n ak-mcp-introspector exec deploy/ak-mcp-introspector -- \
  ak-mcp-introspector sandbox-probe /opt/ak/job.json
```

## Continuous integration

The `mcp-sandbox` workflow (`.github/workflows/mcp-sandbox.yml`) runs on
changes to the worker, its fixtures, this deployment or the workflow, weekly
and on demand. On a GitHub-hosted Ubuntu runner it does the following:

1. It installs gVisor and registers `runsc` with Docker.
2. It builds `ak-mcp-introspector` and the guest image
   `sandbox-check/Dockerfile`, a stdio MCP server in POSIX shell, then pushes
   the image to a local registry that stands in for AK's OCI repository.
3. It runs `ak-mcp-introspector sandbox-probe` with `AK_MCP_SANDBOX_RUNTIME=runsc`.
   The job passes only if the guest answered under gVisor: the outcome is
   `ok`, the tool `echo` was listed, and the kernel the guest reports is not
   the runner's (gVisor implements its own).
4. It checks that the same probe is refused without a runtime.
5. It checks that a container on an internal network like `ak-mcp-sandbox`
   cannot reach the internet.
6. It validates the compose file and the Kubernetes manifests.

The workflow does not cover npm or PyPI guests, which need a running AK to
install from, or the Kubernetes launcher, which needs a cluster with a gVisor
RuntimeClass. Those are deployment checks: run `sandbox-probe` against your
own AK with a job document for a published server.
