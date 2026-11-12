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
| The internal network, cloud metadata | A guest that can open connections can scan and pivot, or send data out. | Each npm or PyPI guest gets an internal network of its own, created by the worker for that run and removed after it: no route out, no DNS for outside names, and no member but the guest and a TCP forwarder that answers on the AK hostname and forwards to AK's address. On Kubernetes, a NetworkPolicy allows TCP 443 to AK only, and guest pods get no DNS server. OCI guests run with `--network=none`. |
| Other guests | A guest that can reach another guest can attack the server running in it, or tamper with its install ([#5447](https://github.com/artifact-keeper/artifact-keeper/issues/5447)). | No two guests share a network (see [Guest networks](#guest-networks-option-a)). Membership of a shared bridge is not a boundary: containers on one bridge reach each other. On Kubernetes, the default-deny policy gives guest pods no ingress. |
| Artifact Keeper credentials | The worker holds an `mcp:introspect` token. In Option A the worker, rootless Podman and the gVisor sentry all run as `ak-sbx`, so a guest that escapes the sentry runs as the worker's user. | The token can only claim jobs and post results. Guests never see it: the worker passes them only placeholder secrets (`AK_PLACEHOLDER_<NAME>`). It is never in the environment: systemd opens the root-only `/etc/ak-mcp-introspector/token` and hands it over as standard input (`--token-file -`), and the worker makes itself non-dumpable (`PR_SET_DUMPABLE=0`), so another `ak-sbx` process can read neither a file holding the token nor the worker's `/proc/<pid>/environ` or memory. Guests install anonymously, so map public, read-only repositories for packages that should be introspected. |
| Other jobs | A guest could persist between jobs. | A fresh container and a fresh network per attempt, both removed after the run; jobs run one at a time per worker, and the guest is killed at the wall clock. |

What this deployment does not cover: a guest can still talk to the AK
instance it installs from (it needs to), and gVisor reduces but does not
remove kernel attack surface. A microVM runtime is the stronger choice where
the host supports nested virtualisation.

### What isolation holds

- **With gVisor (`runsc`).** The guest's system calls go to gVisor's
  user-space kernel (the sentry), not to the host kernel. The sentry itself
  uses a small, filtered set of host system calls, so a bug in the Linux
  kernel is much harder to reach from the guest. If the guest escapes the
  sentry, it runs on the host as the user that runs the worker (`ak-sbx` in
  Option A), with that user's files and processes. In Option A that
  includes the worker process, but not its token
  ([#5390](https://github.com/artifact-keeper/artifact-keeper/issues/5390)):
  the token is in no file and no environment that user can open (systemd
  passes the root-only token file as the worker's standard input), and the
  worker is non-dumpable, so its `/proc/<pid>/environ` and memory are
  root-owned. The escaped guest can still use that user's rootless Podman
  and disturb or kill the worker, so keep the host dedicated to it.
- **Without gVisor (plain `runc` or `crun`).** The guest is an ordinary
  container: namespaces, a seccomp filter and dropped capabilities, sharing
  the host kernel. Any kernel bug the guest can reach through the allowed
  system calls is a host compromise. This is why the worker refuses to run
  a guest without a runtime unless `AK_MCP_SANDBOX_ALLOW_DEFAULT_RUNTIME=true`.
  Do not set it outside a test.

### "Install only from AK" is a network control

The worker passes `--registry` (npm) and `--default-index` (PyPI) with AK's
URL and drops variables that would re-route the package manager. That
decides where a well-behaved installer fetches from. It does not stop
anything else: the install scripts and the server are attacker code, and
they can open a connection to any host they like. Only the network stops
them: the guest's own internal network and the forwarder (Option A), or
the NetworkPolicy and the missing DNS server (Option B). Do not loosen
either on the grounds that the worker already points the installer at AK.

### Guest networks (Option A)

Every guest on one bridge network can connect to every other: a bridge is a
switch, and neither rootless Podman nor Docker filters traffic between
members of the same network. Earlier releases put every npm and PyPI guest
on one internal network, `ak-mcp-sandbox`, and an install script in one
guest could connect to the server in another
([#5447](https://github.com/artifact-keeper/artifact-keeper/issues/5447)).

The worker now gives each npm or PyPI guest a network of its own. For every
attempt it runs, with the guest's fresh name `ak-mcp-sbx-<job>-<random>`:

1. `<engine> network create --internal --label=... <name>`: a bridge with
   no route out. A guest on it has a route to its own subnet only, and the
   engine's DNS answers only for the members of that network.
2. `<engine> network connect --alias <AK host> <name> ak-gateway`: the
   forwarder joins it, under AK's host name, so the guest's lookup of the
   AK host returns the forwarder's address on this network. The name is the
   host of the job's `akBaseUrl`, which is the backend's public base URL
   (the worker's `AK_URL` only for a job that carries none).
3. `<engine> container inspect --format '{{(index
   .NetworkSettings.Networks "<name>").IPAddress}}' ak-gateway`: the
   forwarder's address on this network (the same template works with
   Docker and Podman). If it cannot be read, the guest is not started.
4. `<engine> run --network=<name> --add-host=<AK host>:<that address>
   ...`: the guest, whose only peer is the forwarder. It finds AK through
   its `/etc/hosts`, not the engine's DNS: a gVisor guest on an internal
   Docker network cannot reach Docker's embedded DNS server, so the alias
   alone would leave it unable to find AK.
5. After the run, whatever the outcome: `<engine> rm -f <name>`,
   `<engine> network disconnect -f <name> ak-gateway`, `<engine> network rm
   <name>`. At startup, and every 10 minutes while it is idle, the worker
   also removes the guests and guest networks that a crashed run or a
   failed cleanup left behind (by their owner label); a teardown command
   that fails is logged as a warning naming the command.

If step 1, 2 or 3 fails (the engine cannot create the network, the
forwarder is not running, the alias is refused, its address cannot be
read), the guest is not started: the job
is `start_failed` with the engine's message and is retried. A guest never
runs on a network the worker did not just create for it.

What holds, and what it rests on:

- **Guest to guest: no.** Two guests are never on one network. A guest has
  no route to another guest's subnet, and it cannot add one: it has no
  capabilities (`--cap-drop=ALL`), so no raw sockets and no route changes.
- **Guest to forwarder: TCP 80 and 443 only**, the ports nginx listens on.
  The forwarder forwards only to `ak-upstream` (AK's address) and does not
  route between its networks: the compose file turns IP forwarding off in
  its network namespace (`net.ipv4.ip_forward=0`,
  `net.ipv6.conf.all.forwarding=0`). Do not rely on a default: a new
  network namespace inherits the host's setting, which is on wherever
  Docker or a router role enabled it. It has no capabilities but the four
  nginx needs.
- **Guest to the forwarder's other networks: no.** The forwarder joins the
  networks of all guests running at the same time, but a guest reaches it
  only on the address of its own network; it has no route to the others.
- **Guest to anything else: no.** An internal network has no default
  route and no forwarding of outside DNS names. The bridge address itself
  (the engine's DNS server, where the guest can reach it) answers only
  names of that network.
- **OCI guests** have no network (`--network=none`), and no network is
  created for them.

What remains: the forwarder is **one process joined to every live guest
network**. It is the single shared point between concurrent guests. A
guest that could compromise nginx's stream proxy (a bug in nginx, not in
anything the guest is allowed to do) would sit on all of those networks at
once. Keep it minimal: the stock nginx image pinned by digest, read-only,
the four capabilities, `no-new-privileges`, no HTTP or TLS processing, and
forwarding off. Jobs run one at a time per worker, so concurrent guests
come from several workers sharing one host and one forwarder; one
forwarder per worker (each worker's `AK_MCP_SANDBOX_GATEWAY` naming its
own) removes even that.

`AK_MCP_SANDBOX_NETWORK`, which named the shared network, is retired. A
worker started with `--sandbox` while it is set (or with an empty
`AK_MCP_SANDBOX_GATEWAY`) **does not start**: it exits with an error that
says so, before it claims anything. Skipping the upgrade step stops the
worker; it does not lose jobs, which stay queued until a worker that can
run them claims them. `AK_MCP_SANDBOX_GATEWAY` names the forwarder's
container (default `ak-gateway`).

The backend's public base URL must use a host name, not an IP address: the
guest reaches AK only through the forwarder's alias, and a guest told to
connect to an IP address would find no route to it. A job whose
`akBaseUrl` is an IP address is reported `start_failed` (a deployment
problem, retried), not stored as the server's state.

When several workers share one host, give each a unique
`AK_MCP_INTROSPECTOR_ID`. A worker removes the leftovers labelled with its
own id; two workers with the same id (the default is `ak-mcp-introspector`)
would remove each other's live guests and detach the forwarder from each
other's guest networks.

This was checked with rootless Podman 6.1 (netavark, crun): a guest on its
own network reached the forwarder under the alias, had no default route,
could not resolve outside names, and failed to reach a second guest, the
forwarder's address on the second guest's network, and the internet (which
a container on the forwarder's egress network reached); with both guests
on one network, the second guest was reachable. Check your own host with `sandbox-check/guest-isolation-check.sh`
(step 7 below).

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

   Rootless gVisor needs delegated cgroups v2. Without them it runs only
   with `runsc --ignore-cgroups`, and **that flag removes the memory, pids
   and CPU limits**: `--memory`, `--pids-limit` and `--cpus` are accepted
   but no longer enforced, so one guest can exhaust the host. Delegate
   cgroups to the user instead. On systemd hosts, add a drop-in for
   `user@.service` (for example
   `/etc/systemd/system/user@.service.d/delegate.conf`):

   ```ini
   [Service]
   Delegate=cpu cpuset io memory pids
   ```

   then `systemctl daemon-reload` and restart the user's session (or reboot).
   Check as `ak-sbx` with `podman info`: `cgroupManager` should be
   `systemd`, `cgroupVersion` `v2`, and `cgroupControllers` should list
   `memory`, `pids` and `cpu`. Then check gVisor with `podman --runtime=runsc
   run --rm alpine dmesg`; the first line names gVisor.
3. **Forwarder.** As `ak-sbx`, edit
   `deploy/mcp-introspector/compose.sandbox-network.yaml`: replace
   `203.0.113.10` (the `ak-upstream` entry in `extra_hosts`) with the
   address AK's public host name resolves to (the host of the backend's
   public base URL, which jobs carry as `akBaseUrl`). Then run `podman-compose -f
   compose.sandbox-network.yaml up -d`. This starts the forwarder
   `ak-gateway` on its own way out, `ak-mcp-sandbox-egress`, which no guest
   joins. There is no shared guest network: the worker attaches the
   forwarder to each guest's own network for the length of a run, under the
   AK hostname as an alias ([Guest networks](#guest-networks-option-a)).
   The forwarder sends TCP 443 (and 80) on to `ak-upstream`, the real AK.
   TLS stays end to end and the certificate stays AK's.
   `nginx-ak-gateway.conf` must not name the AK hostname as its upstream:
   inside the forwarder that name is its own alias, so it would forward
   every connection back to itself. If AK's address changes, update
   `extra_hosts` and recreate the forwarder. The forwarder must be running
   for npm and PyPI jobs: while it is not, they fail with `start_failed`
   and are retried. If you upgrade from a release with the shared network,
   remove it (`podman network rm ak-mcp-sandbox`) and unset
   `AK_MCP_SANDBOX_NETWORK`.
4. **Images.** Mirror the guest images (`AK_MCP_SANDBOX_NODE_IMAGE`,
   `AK_MCP_SANDBOX_PYTHON_IMAGE`) through an AK OCI repository, pin them by
   digest, and pull them once as `ak-sbx`. Guests run with `--pull=missing`.
5. **Service.** Install `systemd/ak-mcp-introspector.service` and
   `systemd/ak-mcp-introspector.env.example` (as
   `/etc/ak-mcp-introspector.env`; it holds no secret). Put the
   `mcp:introspect` token in `/etc/ak-mcp-introspector/token`, mode 0600,
   owner root (`install -d -m 0700 /etc/ak-mcp-introspector`). The unit runs
   as `ak-sbx` with `AK_MCP_SANDBOX_ENGINE=podman`,
   `AK_MCP_SANDBOX_RUNTIME=runsc` and `AK_MCP_SANDBOX_GATEWAY=ak-gateway`;
   systemd opens the token file before it drops to `ak-sbx` and passes it as
   standard input (`StandardInput=file:`, `--token-file -`), so the token is
   in no file and no environment that `ak-sbx` can read. Do not set
   `AK_MCP_INTROSPECTOR_TOKEN`: an environment value stays readable in
   `/proc/<pid>/environ` (the worker warns when it gets one).
6. **Egress of the worker itself** (remote probes). Allow the AK host and
   public addresses only: drop RFC 1918, CGNAT, link-local (cloud metadata),
   loopback and the IPv6 equivalents at the host firewall. The worker's own
   address checks are a second layer.
7. **Check before enabling.** Run a real sandboxed probe with no backend:

   ```sh
   sudo -u ak-sbx env AK_MCP_SANDBOX_RUNTIME=runsc \
     ak-mcp-introspector sandbox-probe deploy/mcp-introspector/sandbox-check/job.example.json
   ```

   It exits `0` only when the guest answered (`"outcome": "ok"`). Then
   check that guests cannot reach each other, with the same engine and
   runtime:

   ```sh
   sudo -u ak-sbx env ENGINE=podman RUNTIME=runsc \
     sh deploy/mcp-introspector/sandbox-check/guest-isolation-check.sh
   ```

   It builds the per-guest topology with throwaway names and passes only
   if a guest reaches the forwarder under the alias but not a second
   guest, the forwarder's address on the second guest's network or the
   internet; has no default route; cannot resolve an outside name; a guest
   sharing the second guest's network does reach it (so a probe that
   cannot connect at all does not pass); the second guest recorded exactly
   that one connection; and IP forwarding is off in the test forwarder and
   in the running `ak-gateway` (`GATEWAY=` names another). The internet
   check counts only when a container on the egress network can reach the
   internet (`EGRESS_HOST`/`EGRESS_PORT`, default `1.1.1.1:80`); otherwise
   it is reported inconclusive and the missing default route decides.
   `SHARED=1` puts both guests on one network, the old layout: the check
   must then fail. Then set
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
| `networkpolicy.yaml` | Guests: no ingress, egress only to AK on TCP 443, no DNS. Worker: egress to the API server, AK and public addresses, never to private ranges or metadata. |
| `launcher-configmap.yaml` | `k8s-launcher.sh`: guest spec JSON in, `kubectl run --attach` with the restricted security context, runtime class and wall clock out. |
| `deployment.yaml` | One worker replica (jobs run one at a time per worker), token from a Secret, the launcher mounted. Build the image from the binary and `kubectl`. |

The launcher labels each guest pod `ak-mcp-sandbox/network: ak-only` (npm,
PyPI) or `none` (OCI). The default-deny policy blocks all traffic, and only
`ak-only` pods get egress, to AK on TCP 443.

Guests get no DNS either. kube-dns resolves names outside the cluster by
forwarding them, so a guest that may query it can send data out encoded in
the names it looks up. Instead the launcher gives each guest pod
`dnsPolicy: None` with a loopback nameserver, and a `hostAliases` entry
that maps `AK_MCP_SANDBOX_AK_HOST` (the host of `AK_URL`) to
`AK_MCP_SANDBOX_AK_IP` (the address of the AK ingress or load balancer the
guest should reach). Set both in `deployment.yaml`. Use a stable address:
an ingress whose address changes needs the variable and the policy updated
together.

Edit the placeholder addresses in `networkpolicy.yaml` first: the AK
ingress (the same address as `AK_MCP_SANDBOX_AK_IP`) and the API server.
The policies are IPv4 only, so on a dual-stack cluster add the IPv6 ranges
as well. Check that your CNI enforces a policy from a pod's first packet:
with kind's default CNI (kindnet), a new pod's connections in its first
few seconds were let through before the policy applied.

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
5. It checks that a container on an internal network cannot reach the
   internet.
6. It runs `sandbox-check/guest-isolation-check.sh` under `runsc`: a guest
   on its own network reaches the forwarder and nothing else, and the same
   check fails with both guests on one network, because the second guest
   was reached (the step asserts that line, so a check that could not run
   does not count as the expected failure).
7. It runs `sandbox-probe` on an npm job with the real Docker CLI and a
   stand-in forwarder: the guest reaches the forwarder under the AK host
   name, and afterwards no guest container or guest network is left and
   the forwarder is back on its egress network only. It also checks that
   a worker with `AK_MCP_SANDBOX_NETWORK` set refuses to run.
8. It validates the compose file and the Kubernetes manifests.

The workflow does not cover npm or PyPI guests, which need a running AK to
install from, or the Kubernetes launcher, which needs a cluster with a gVisor
RuntimeClass. The isolation check exercises the topology the worker builds,
with Docker; the worker's own commands for it are pinned by unit tests and
run once against Docker by step 7.
Malicious npm and PyPI guests against an independent second-guest recorder
on rootless Podman are covered by artifact-keeper-test. Those are deployment checks: run `sandbox-probe` against your
own AK with a job document for a published server.
