# Self-hosted CI jobs in throwaway VMs (`ak-vm`)

Tracking issue: #6072 (epic #6081).

`ak-vm-runner` is a small service for a KVM host. It runs every GitHub
Actions job that asks for `runs-on: ak-vm` in its own virtual machine. Each VM
has its own kernel and its own `dockerd`, runs exactly one job, and is then
destroyed with its disk. No container on the host runs privileged for that
job, and nothing carries over from one job to the next except a read-only
golden image and, if you configure one, a read-only cache disk.

The service needs no Kubernetes or container-runtime change. It runs beside
whatever else is on the host (on `rocky`, beside the kubeadm cluster and the
ARC runner pools) and only uses libvirt, qemu-kvm and systemd.

Code: [`scripts/ci/vm-runner/`](../../scripts/ci/vm-runner/). Tests:
[`scripts/ci/test-vm-runner.sh`](../../scripts/ci/test-vm-runner.sh). The
Kata Containers alternative is evaluated in
[`kata-runtimeclass-plan.md`](kata-runtimeclass-plan.md).

## How a job flows

```
 ak-vm-runner.service (user akvm)                 GitHub
 ───────────────────────────────                  ──────
 every 15 s: fewer than AKVM_VM_COUNT VMs (default 1)?
   │ yes
   ├─ POST /orgs/{org}/actions/runners/generate-jitconfig ──► runner "akvm-rocky-<time>-<rand>"
   │      labels: [ak-vm], one-time registration                 (label ak-vm only)
   ├─ qemu-img: overlay disk on images/golden/current.qcow2
   ├─ seed.iso (cloud-init NoCloud) carrying the JIT config
   └─ virsh define + start  ──►  VM boots
                                   ak-vm-job.service:
                                     deletes the JIT file, waits for dockerd,
                                     run.sh --jitconfig  ◄── one job ──  runs-on: ak-vm
                                     job ends → runner exits → poweroff
 VM is "shut off"
   ├─ audit: vm_destroyed reason=job_finished (+ the job the guest reported)
   ├─ DELETE runner registration (404 = already gone, which is normal)
   └─ virsh undefine, rm -rf vms/<name>
```

The job sees a normal Ubuntu 24.04 machine. The `runner` user has
passwordless `sudo` and is in the `docker` group, as on a GitHub-hosted
runner. That is safe because the VM is the security boundary.

Other ways a VM ends, all audited with a `reason`:

| reason | when |
|---|---|
| `job_finished` | the guest powered off after the runner exited |
| `disk_critical_idle`, `disk_critical_paused` | the state filesystem fell below `AKVM_CRIT_FREE_PCT` |
| `boot_timeout` | no `runner_start` on the console within `AKVM_BOOT_TIMEOUT` (600 s) |
| `idle_recycle` | no job for `AKVM_IDLE_RECYCLE_SECONDS` (4 h). The registration is removed first, and GitHub refuses that (422) while a job is assigned, so a job is never cut off by this |
| `scale_down` | more VMs than `AKVM_VM_COUNT`, or any while drained: one idle VM per pass, registration removed first as for `idle_recycle`. Busy and still-booting VMs are left alone |
| `stale_shape` | an idle VM whose vcpus/memory differ from the config (registration first, as above). A busy VM keeps its shape until its job ends |
| `max_age` | older than `AKVM_MAX_VM_SECONDS` (8 h), even mid-job |
| `guest_stopped_*` | the VM stopped without reporting `runner_exit` (crash, OOM inside the guest) |
| `operator_destroy_all` | `ak-vm-runner destroy-all` |

## Isolation

- **Kernel:** each job has its own guest kernel under KVM. `qemu-kvm` runs as
  the unprivileged `qemu` user. The guest's `dockerd` is privileged only
  inside the guest.
- **Disk:** each VM writes to its own qcow2 overlay. The golden image is a
  read-only (0444) backing file. The overlay is deleted with the VM.
- **Network:** VMs sit on their own libvirt NAT network, `ak-vm`
  (192.168.151.0/24, bridge `virbr-akvm`). The `ak-vm-egress` nwfilter
  (`libvirt/nwfilter.xml`) is attached to every VM interface. It allows DNS
  and DHCP to the network's own dnsmasq, drops every connection to private,
  CGNAT (tailscale), link-local, loopback and multicast ranges, and allows
  the rest of the internet. A job VM therefore cannot reach the host's
  services (sshd, kube-apiserver, kubelet, NodePorts), the LAN, pod or
  service IPs, or another job VM. It also drops DHCP answers from a VM
  (so no rogue DHCP server for a sibling), all broadcast except the DHCP
  request, and all IPv6. Every VM interface is an *isolated* bridge port,
  so VMs cannot exchange even layer-2 frames (ARP, link-local IPv6); they
  only reach the gateway. The guest boots with `ipv6.disable=1`. The filter
  uses only iptables/ip6tables-backed rules, so the host needs no ebtables.
- **Credentials:** the GitHub token that mints JIT registrations stays on the
  host (`/etc/ak-vm-runner/github-token`, 0640 root:akvm). It is passed to
  `curl` through a pipe, read fresh on every call, and never written
  anywhere else or put on a command line. A VM only ever receives its own
  single-use JIT config: the guest deletes its copy before the runner
  starts, and the host ejects the seed ISO from the VM and deletes it once
  the runner reports `runner_start`. The job itself can still read the
  config while it runs (it is in the runner's arguments and in cloud-init's
  cache, and the job has `sudo`). That is the job's own single-use runner
  registration, and it is dead once the job ends.
- **No inbound access:** the image has `ssh` masked and no user with a
  password. The serial console log is the only window into a VM.
- **Resources:** every VM runs in `machine-akvm.slice`, which hard-caps memory
  (`MemoryLimit=16G`: one 14 GiB job VM, ~1 GiB qemu and page-cache
  overhead, ~1 GiB slack) and CPU (`CPUQuota=800%`, the job VM's 8 vCPUs)
  for all VMs together. The controller reads that limit at runtime
  (`systemctl show -p MemoryLimit -p MemoryMax`, or `AKVM_SLICE_MEMORY_MIB`)
  and starts no VM unless the running ak-vm domains (job and image-build
  VMs, guest memory + 1 GiB each) plus the new one and its 1 GiB fit. The
  4 GiB image-build VM does not fit beside a job VM, so `build-image` sets
  the drain flag (if it is not set already), waits up to
  `AKVM_IMAGE_WAIT_SECONDS` (8 h) for the job VM to go (an idle one is
  recycled at once, a busy one finishes its job), builds, and then removes
  the drain flag only if it set it. Before creating a VM the controller also checks that the state
  filesystem has at least `AKVM_MIN_FREE_PCT` (35 %) free (the kubelet starts
  evicting pods at 20 % on rocky's `/home`). It also checks that
  `MemAvailable` covers the VM plus `AKVM_MIN_HOST_AVAIL_MIB` (24 GiB).
  If free space later falls below `AKVM_CRIT_FREE_PCT` (25 %), every pass
  destroys paused VMs (qemu pauses a guest whose disk write fails) and
  idle ones. A VM running a job is never destroyed for disk.

## What jobs share: the build cache

By default, nothing. Builds that use the registry cache (`cache-from` and
`cache-to` with `type=registry`, as Docker Publish does) work exactly as on
GitHub-hosted runners.

A read-mostly shared cache is available as an option. Set `AKVM_CACHE_IMAGE`
to a raw disk image (for example `/home/ak-vm-runner/cache/cache.img`) and
every VM gets it as `/dev/vdb`, attached read-only and shareable. A job can
read it (`sudo mount -o ro /dev/vdb /mnt/cache`) but cannot change it. Only
the operator refreshes it, offline:

```bash
sudo runuser -u akvm -- truncate -s 50G /home/ak-vm-runner/cache/cache.img.new
sudo mkfs.ext4 -F /home/ak-vm-runner/cache/cache.img.new
# mount it on the host, fill it (e.g. a buildx cache exported with
# --cache-to type=local,dest=...), unmount, then atomically:
sudo runuser -u akvm -- mv /home/ak-vm-runner/cache/cache.img.new /home/ak-vm-runner/cache/cache.img
```

Running VMs keep the inode they opened. New VMs get the new image.

## Audit trail

| where | what |
|---|---|
| `journalctl -u ak-vm-runner` | the controller's log; every audit event is also printed here as `audit {json}` |
| `/home/ak-vm-runner/log/audit.jsonl` | one JSON object per lifecycle event, append-only (`chattr +a`, so the service user cannot rewrite history) |
| `/home/ak-vm-runner/log/console/<vm>.log` | the VM's full serial console: boot, `dockerd` and runner start, and the job hooks. Kept for `AKVM_CONSOLE_RETENTION_DAYS` (30) |
| `journalctl -u ak-vm-runner-image` | golden image builds |
| `images/golden/ak-vm-<time>.{sha256,manifest}` | each golden image's digest and what is in it (Ubuntu, kernel, runner, docker, buildx, gh, buildkit digest) |

Events: `controller_started`, `controller_stopped`, `vm_created` (runner name
and id, labels, image and its sha256, size), `jit_failed`,
`vm_start_failed`, `vm_destroyed` (reason, lifetime, the HTTP status of the
runner removal and the guest-reported job), `vm_orphan_removed`,
`image_build_waiting` (no room in the slice yet), `image_build_started`,
`image_built`, `image_build_failed`, `image_pruned`, `drain_on` and
`drain_off` (`by=build-image` when the image build set or cleared it).

Fields prefixed `guest_` (repository, run id, job, sha, ref, actor, the
runner's exit code) come from the job hooks inside the VM. Once a job runs,
the guest is under the job's control, so treat them as claims. The
`job_started` fields are taken from the FIRST such record, which the
runner's hook prints before any step runs. `guest_job_started_records`
greater than 1 means the job printed a forged one. To confirm
which job ran where, compare them with GitHub's own record: the job's
`runner_name` in `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs`
equals the `vm` field. Everything else in a record is written by the host.

Useful queries:

```bash
# Every job a VM ran today, with the run it claimed
jq -c 'select(.event=="vm_destroyed") | {ts, vm, reason, guest_repository, guest_run_id, guest_job, guest_code}' \
  /home/ak-vm-runner/log/audit.jsonl
# Which image a given runner booted
grep '"vm":"akvm-rocky-20261116..."' /home/ak-vm-runner/log/audit.jsonl
```

## Operating it

```bash
sudo /usr/local/sbin/ak-vm-runner status            # VMs, their runners, last guest event
sudo systemctl status ak-vm-runner                  # the loop
sudo systemctl start ak-vm-runner-image             # build a new golden image now
```

`/usr/local/sbin/ak-vm-runner` (root only; el8 `sudo` leaves `/usr/local/sbin` off its
PATH, hence the full path) runs a subcommand as `akvm` with the config
loaded: `status`, `drain`, `undrain`, `destroy-all`, `once`, `build-image`.

- **Pause new jobs:** `drain`. No VM is created, and idle VMs are recycled
  one per pass (`scale_down`; the registration goes first, so a job that was
  just assigned keeps its VM). Running jobs finish. `destroy-all` removes
  every VM at once, mid-job included.
- **Stop the service:** `systemctl stop ak-vm-runner`. Running VMs keep
  running, and the next start adopts them. To stop everything:
  `systemctl stop ak-vm-runner`, then `sudo /usr/local/sbin/ak-vm-runner destroy-all`.
- **Update the runner version:** set `AKVM_RUNNER_VERSION` and
  `AKVM_RUNNER_SHA256` in `/etc/ak-vm-runner/config.env` (the sha256 is in the
  actions/runner release notes), then build an image. The runner
  self-updates when GitHub demands a newer one, at the cost of a slower
  first job, so rebuild soon after a runner release. The weekly
  `ak-vm-runner-image.timer` (disabled by default) picks up Ubuntu and docker
  updates.
- **Change the pool size or VM shape:** set `AKVM_VM_COUNT`,
  `AKVM_VM_VCPUS` and `AKVM_VM_MEMORY_MIB` in `/etc/ak-vm-runner/config.env`.
  Size `MemoryLimit` in `/etc/systemd/system/machine-akvm.slice` to at least
  `count × (memory + 1 GiB) + 1 GiB` and `CPUQuota` to `count × vcpus × 100%`
  (add 4 GiB + 1 GiB if the image build should run beside a full pool
  instead of draining it). Apply the slice without restarting it:
  `systemctl daemon-reload && systemctl set-property --runtime machine-akvm.slice MemoryLimit=<n>G CPUQuota=<n>%`,
  then `systemctl restart ak-vm-runner`. A smaller count or a new shape takes
  effect on the idle VMs at once (`scale_down`, `stale_shape`); a VM running
  a job keeps its shape until the job ends. The slice is also counted in
  the ARC budget (see [Capacity on rocky](#capacity-on-rocky)): change both.

## Installing it on your own KVM host

Requirements: an x86_64 Linux host with `/dev/kvm`, libvirt with the QEMU
driver and the nwfilter driver, `qemu-img`, `genisoimage`, `jq`, `curl` and
`flock`. Tested on Rocky Linux 8.10 (libvirt 8.0, qemu-kvm 6.2). The guest is
Ubuntu 24.04. You also need a GitHub credential that can manage
organization self-hosted runners: a GitHub App with the *Self-hosted
runners: write* organization permission (preferred), or a token with
`admin:org`. Repository-level runners work too, but the script calls the org
endpoints, so point `AKVM_ORG` at an organization.

```bash
git clone https://github.com/artifact-keeper/artifact-keeper.git && cd artifact-keeper
sudo scripts/ci/vm-runner/install.sh
sudoedit /etc/ak-vm-runner/config.env            # org, runner group, labels, pool size
sudo install -m 0640 -o root -g akvm /dev/stdin /etc/ak-vm-runner/github-token   # paste, Ctrl-D
sudo systemctl start ak-vm-runner-image          # first golden image, 10-20 min
sudo systemctl enable --now ak-vm-runner
```

The state lives in `/home/ak-vm-runner`. On another layout, set
`AKVM_STATE_DIR` and change `ReadWritePaths=` in both units. If
192.168.151.0/24 is in use on your host, edit `libvirt/network.xml` and the
gateway address in `libvirt/nwfilter.xml`. With SELinux enforcing, label the
state directory for libvirt:
`semanage fcontext -a -t virt_image_t '/home/ak-vm-runner/(vms|images)(/.*)?' && restorecon -R /home/ak-vm-runner`.

To remove it: `sudo scripts/ci/vm-runner/uninstall.sh`, which keeps the
images and the audit log, or add `--purge` to remove those too.

## Using it from a workflow

```yaml
jobs:
  build:
    runs-on: ak-vm
```

Nothing else changes. `docker`, `docker buildx` (with the `docker-container`
driver that `docker/setup-buildx-action` creates), native amd64 builds,
`cosign`, `actions/attest-build-provenance` and OIDC (`id-token: write`)
behave as on `ubuntu-24.04`. Only amd64 is provided, so arm64 legs stay on
`ubuntu-24.04-arm`.

## Capacity on rocky

The VMs use host memory that the Kubernetes scheduler does not see. The
`machine-akvm.slice` cap (16 GiB / 8 CPUs by default: one 8 vCPU / 14 GiB
VM) bounds it, and the ARC budget in artifact-keeper-arc-runners counts
exactly that cap as reserved: `budget/rocky.yaml`, `reserved.ak_vm` (16Gi /
8 CPU). The two must match: change one and you must change the other in the
same change. Before the pool grows, raise both together (and lower the ARC
pools by the same amount). Adding the slice cap to the kubelet's
`systemReserved` needs a maintenance window (see the #6072 change plan).

Docker Publish's amd64 `build-openscap` and `build-scanner-adapter` legs run
on this pool (#6094). One VM is enough for them. They peak at about 1.2 to
1.4 GiB in the guest (1.0 to 1.6 GiB per pod on the old dind pool, measured
over 41 runs each) and take 2 to 4 minutes. Concurrent Docker Publish runs
queue their legs one VM at a time: each next VM is ready about 30 to 40 s
after the last job ends, so four legs take about 12 minutes. That is well
inside the ~55-minute backend amd64 leg the merge jobs already wait for.
Nothing can deadlock, because a job holds the VM only while it runs. The
watchdog leaves such runs alone: `publish-preflight` has already started, and
its started-run rule (#6289) acts only on a job that has waited 45 minutes
for a runner.
