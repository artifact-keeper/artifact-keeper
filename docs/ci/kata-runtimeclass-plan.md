# Kata Containers RuntimeClass for the self-hosted runners: evaluation and change plan

Tracking issue: artifact-keeper/artifact-keeper#6072 (parent epic #6081).
Status: paper plan. Nothing in this document has been applied to `rocky`.
Date of the host survey: 2026-11-16.

## Summary

Running the ARC runner pods under Kata Containers on `rocky` is possible, but
it is the riskier of the two options for meeting #6072, and it is the only one
that touches the container runtime of a host that also runs production.

Recommendation: build the standalone libvirt/KVM ephemeral-VM runner service
(`ak-vm`) and move Docker Publish to it first. Do not enable Kata on `rocky`
now. If Kata is wanted later, validate it first in a nested EL8 VM on `rocky`
(nested KVM is enabled there), and revisit after the host moves to EL9 and
cgroup v2. Kubernetes 1.35 refuses cgroup v1 nodes by default, so that move is
coming anyway.

The reasons, in order of weight:

1. The pods we would move do not fit Kata as they are written. Docker-in-docker
   puts `/var/lib/docker` on a hostPath, and Kata shares hostPaths through
   virtio-fs, which cannot be an overlayfs upper layer. The persistent
   buildkit-cache slots depend on `flock` across pods, and that cannot work
   between separate guest kernels. Both need redesign before the first job
   runs.
2. Memory accounting changes in a way the current budget does not model. A
   Kata pod's VM is sized from container **limits** plus a base size, and
   guest page cache is not handed back to the host. A docker build pod sits
   close to its limit (16 to 20 GiB) for the whole job, not at the 6 GiB it
   requests today. On a single node already budgeted tightly by requests, that
   is a real risk to production pods (eviction or host OOM).
3. Kata 4.x (current 4.3.1; the 3.x line ended at 3.32.0) defaults to the Rust
   runtime. Our host is EL8 kernel 4.18 with cgroup v1, the `cgroupfs` cgroup
   manager, and cri-o rather than containerd. That combination gets little
   upstream testing.
4. The cri-o change can be made with a reload (SIGHUP), which cri-o 1.31.5
   supports for the runtimes table. If anything forces a cri-o **restart**,
   though, the blast radius on this host is the whole node. Every conmon
   process sits in `crio.service`'s cgroup, and the unit uses
   `KillMode=control-group` (observed, see below).

The libvirt service has none of these couplings. Its costs are its own code,
and capacity that sits outside the Kubernetes scheduler and has to be reserved
explicitly.

## 1. What is on rocky today

Everything in this section was observed read-only on 2026-11-16 (`ssh
khan@rocky`), unless marked "docs" or "inferred".

### Host

| Item | Observed |
|---|---|
| OS / kernel | Rocky Linux 8.10, `4.18.0-553.94.1.el8_10.x86_64` |
| CPU | 2 x Xeon E5-2699 v4: 2 sockets x 22 cores x 2 threads = 88 logical CPUs (44 physical cores), 2 NUMA nodes, VT-x |
| Memory | 156 GiB total; about 55 GiB used, 84 GiB buff/cache, 99 GiB available at survey time |
| KVM | `/dev/kvm` (root:kvm 0666); `kvm_intel` loaded, `nested=1`, `ept=Y`, `unrestricted_guest=Y`; `/etc/modules-load.d/kvm.conf` loads kvm, kvm_intel |
| vhost / vsock | `/dev/vhost-net` and `/dev/vhost-vsock` exist (misc devices, autoload on open). Modules `vhost`, `vhost_net`, `vhost_vsock`, `vsock` are present in `/lib/modules` but **not loaded** (`lsmod` shows none). |
| SELinux | **Permissive** (no AVC records today) |
| cgroups | v1 (tmpfs `/sys/fs/cgroup`, separate controller hierarchies) |
| Disks | `/` is 70 G (28 G free), `/home` is 1.8 T xfs (1.1 T free) |
| Virtualization packages | qemu-kvm 6.2.0-53 (el8 module), libvirt 8.0.0-23.4. `libvirtd` and `virtqemud` are inactive (socket-activated), no domains defined, `default` network active (virbr0) |
| Other | `gitlab-runner.service` also runs on the host |

### cri-o

- `cri-o-1.31.5` (pkgs.k8s.io build, Feb 2025), `conmon-2.1.10` (el8 module),
  `runc-1.2.9`, `container-selinux-2.229.0`. No `crun` RPM, but
  `/usr/libexec/crio/{crun,runc,conmon,conmonrs}` ship with the cri-o package.
- There is no `/etc/crio/crio.conf`. Configuration comes only from drop-ins:
  - `02-cgroup-manager.conf`: `cgroup_manager = "cgroupfs"`, `conmon_cgroup = "pod"`
  - `10-crio.conf`: signature policy; `default_runtime = "crun"`; crun and runc tables under `/usr/libexec/crio`
  - `10-runtime.conf`: `default_runtime = "runc"`, runc table replaced with `runtime_path = "/usr/bin/runc"`, `runtime_type = "oci"`
- Live config, read with a GET on the cri-o socket (`/config`), confirms
  `default_runtime = "runc"`, runc at `/usr/bin/runc` with
  `monitor_path = "/usr/bin/conmon"`, crun as a second handler, and
  `drop_infra_ctr = true`. No `kata` handler exists.
- OCI hooks: `hooks_dir = /usr/share/containers/oci/hooks.d`. That directory
  and `/etc/containers/oci/hooks.d` are both empty.
- Storage: overlay, graphroot `/home/containers-storage/storage`
  (`/var/lib/containers` is a symlink to `/home/containers-storage`),
  `overlay.mountopt=nodev,metacopy=on`.
- The unit is stock (`/usr/lib/systemd/system/crio.service`, no drop-ins),
  with `ExecReload=/bin/kill -s HUP $MAINPID` and **`KillMode=control-group`**.
  It has been active since 2026-09-01 (boot, 75 days up).
- **conmon placement:** 97 conmon processes are listed under
  `/system.slice/crio.service`. For the etcd conmon, `/proc/<pid>/cgroup`
  shows `name=systemd`, `memory`, `pids` and `devices` in
  `/system.slice/crio.service`; the other controllers are in the pod cgroup.
  The container processes themselves are entirely in `kubepods/...`.
- Node `status.runtimeHandlers`: `crun`, `runc`, and the default handler.

### kubelet

- kubelet 1.31.14 (kubeadm), `--container-runtime-endpoint=unix:///var/run/crio/crio.sock`.
- `/var/lib/kubelet` is a bind mount of `/dev/mapper/rl00-home[/kubelet]`, so
  emptyDir volumes live on `/home`.
- `config.yaml` says `cgroupDriver: systemd`, but cri-o uses `cgroupfs`, and
  the hierarchy in use is `/sys/fs/cgroup/memory/kubepods` (the cgroupfs
  naming, not `kubepods.slice`). kubelet 1.31 takes the driver from the CRI
  (KubeletCgroupDriverFromCRI, beta and on by default), so the config value
  is ignored. That is inferred from the hierarchy names, not from a kubelet
  log line.
- `systemReserved` 6Gi/1 CPU, `kubeReserved` 2Gi/1 CPU, `evictionHard`
  memory 2Gi, `evictionSoft` memory 6Gi (1m), `maxPods: 250`. Allocatable is
  86 CPU / 146.8 GiB.
- No RuntimeClass objects exist.

### ARC runner pods

- The scale sets ak-ci, ak-docker, ak-e2e and ak-beefy are all on chart
  0.13.1 and are installed with `helm` (scripts/apply.sh), not ArgoCD. The
  controller runs in arc-systems.
- At survey time `ak-docker-runners` had 6 runners. 5 were running jobs of
  `artifact-keeper-test`'s `release-gate.yml` (DTF tiers), so the release
  gate uses this pool for a 6-way fan-out.
- **Drift:** live `helm get values ak-docker-runners` has `maxRunners: 6`
  (helm rev 10, 2026-11-15). `argocd/arc-docker-runners-values.yaml` on the
  default branch of artifact-keeper-arc-runners says `maxRunners: 2`.
- An ak-docker pod (live spec) has:
  - init containers `init-dockerhub-creds`, `init-dind-externals` and
    `init-buildkit-cache` (each 64Mi request / **1Gi limit**), and `dind` as a
    native sidecar (`restartPolicy: Always`, `privileged: true`,
    `docker:dind`, overlay2, 2 CPU / 6Gi request, 12 CPU / 16Gi limit).
  - the runner container (0.5 CPU / 1Gi request, 2 CPU / 4Gi limit).
  - volumes: emptyDirs `work`, `dind-var`, `dind-externals` and
    `docker-config-dir`; **hostPath `/home/runner-dind`** mounted at
    `/var/lib/docker` with `subPathExpr: $(POD_NAME)`; **hostPath
    `/home/runner-cache/buildkit`** mounted at `/cache/buildkit` with flock
    slots; a ConfigMap `daemon.json` (registry mirror); a Secret
    `dockerhub-pull`.
- The hostPath for the buildkit cache is `/home/runner-cache/buildkit`, not
  `/cache/buildkit` (`/cache` does not exist on the host). It holds 4.0 KiB
  in total: the slots exist but nothing uses them yet.
- ResourceQuota `runner-pool-cap`: 92Gi requests.memory, 44 CPU, 16 pods.
  It was at 57Gi / 20.6 CPU / 8 pods at survey time. There is no LimitRange.
  PriorityClasses ak-runner-{ci,docker,e2e,beefy} are -100/-200/-300/-400 and
  non-preempting.
- The `arc-runners` namespace has no Pod Security Admission labels.

## 2. Kata on this host: versions, packaging, hypervisor

### Which Kata

Current upstream releases (GitHub, checked 2026-11-16): 4.3.1 (2026-10-21),
4.3.0, 4.2.0, 4.1.0, 4.0.0 (2026-07-20). The 3.x line ends at 3.32.0
(2026-06-22).

- From the docs and release notes: since 4.0 the Rust runtime (`runtime-rs`)
  is the default. The Go runtime is deprecated and gets only critical and CVE
  fixes. In 4.1 and later, the Go runtime ships in a separate tarball,
  `kata-go-static-<v>-amd64.tar.zst`.
- `kata-static-4.3.1-amd64.tar.zst` is about 1.0 GB. It extracts under
  `opt/kata/`, and contains the runtime-rs shim
  (`/opt/kata/runtime-rs/bin/containerd-shim-kata-v2`), configs under
  `/opt/kata/share/defaults/kata-containers/runtime-rs/`, a Kata-built QEMU,
  cloud-hypervisor, dragonball, guest kernels and images, and virtiofsd. The
  paths come from kata-deploy 4.3.1's `utils/system.rs`.
- No RPM is an option. The distribution `kata-containers` RPM for EL8 (it
  was in CentOS 8 Stream / RHEL 8 for OpenShift sandboxed containers) is 2.x
  era and unmaintained for this use. So the static tarball is the only
  supported path, and kata-deploy installs that same tarball.
- The release publishes **no checksum files**. Verify the download against
  the GitHub asset `digest` field (sha256) from the releases API. See the
  install steps.

Pin 4.3.1, the runtime-rs shim and the `qemu-runtime-rs` config. Keep the Go
runtime (`kata-go-static`, shim `/opt/kata/bin/containerd-shim-kata-v2`,
config `configuration-qemu.toml`) as a fallback if runtime-rs misbehaves on
cgroup v1.

### Hypervisor choice

- **QEMU (Kata-built, shipped in the tarball):** the only realistic choice.
  It supports virtio-fs, memory and CPU hotplug, and block hotplug. The host's
  qemu-kvm 6.2 is not used; Kata runs its own QEMU against `/dev/kvm`.
- **Cloud Hypervisor:** works with virtio-fs. Upstream tests it on recent
  host kernels, and nothing in its docs promises EL8 4.18 (docs, not tested
  here). No advantage for us.
- **Firecracker:** the docs say it needs host kernel 5.10 or 6.1, and it has
  no virtio-fs. With cri-o, every volume and the rootfs would need a
  devmapper or block snapshotter, which cri-o does not provide the way
  containerd does. Excluded.
- **Dragonball** (built-in VMM, runtime-rs only): new in 4.0, little mileage,
  and no reason to choose it here.

### What Kata needs from the host kernel

From the docs (Kata host requirements and `kata-ctl check`), compared with
what we observed:

| Requirement | Host |
|---|---|
| KVM with VT-x, EPT, unrestricted guest | present |
| `vhost`, `vhost_net` (virtio-net acceleration) | module present, not loaded (`/dev/vhost-net` autoloads) |
| `vhost_vsock` (agent channel; Kata 2.x and later use vsock only) | module present, not loaded (`/dev/vhost-vsock` autoloads) |
| `tun` / tc / macvtap for the pod network (flannel veth is bridged into the VM with a tc mirror) | `tun` loaded |
| cgroups v1 or v2 | v1. Kata documents v1 support. With runtime-rs on v1 plus cgroupfs under cri-o, we found no upstream evidence either way, so this must be proven in staging. |
| SELinux | Permissive. If it is ever set to Enforcing, Kata's QEMU needs the `container_kvm_t` policy from container-selinux (present, 2.229). |

The EL8 4.18 kernel carries the KVM, vhost and vsock backports that OpenShift
sandboxed containers relied on for RHEL 8 based nodes (docs; that was Kata
2.x on RHCOS, not 4.x on Rocky). A plain 4.18 version number is therefore not
disqualifying, but nobody upstream tests 4.x on this kernel.

## 3. Does the docker-in-docker runner pod work under Kata?

### Privileged containers inside a Kata pod

cri-o's runtime table supports `privileged_without_host_devices = true`, and
kata-deploy 4.3.1 writes it for every Kata handler (`runtime/crio.rs`). With
it, `privileged: true` grants all capabilities and an unconfined view *inside
the guest*, and no host `/dev` nodes are passed to the VM. That is the
property #6072 asks for: dockerd is root in its own kernel, and the host sees
only a QEMU process and a virtiofsd per pod.

Caveats:
- The QEMU, virtiofsd and shim processes still run as root on the host by
  default. Kata has a rootless VMM option, but it needs the job-mode
  kata-deploy and udev rules, so it is not part of this plan.
- To admission (PSA, if it is ever enabled) the pod is still "privileged".
  Admission does not know about the VM boundary.

### Storage for `/var/lib/docker`

This is the hard blocker in the current pod spec.

- Kata docs (`docs/how-to/how-to-run-docker-with-kata.md`, 4.3.1): virtio-fs
  "cannot be used as a upper layer of overlayfs without a custom patch".
  dockerd may also "silently pick a worse storage driver like vfs". Our pod
  passes `--storage-driver=overlay2` explicitly, so dockerd would fail to
  start instead of degrading silently.
- Today `/var/lib/docker` is the hostPath `/home/runner-dind/<pod>`. Under
  Kata every hostPath is a virtio-fs share, so this mount has to go.
- Options:
  1. **`emptydir_mode = "block-plain"`** in the Kata config (in both the Go
     and runtime-rs configs in 4.3.1). Kata backs each disk emptyDir with a
     block device that it plugs into the guest and formats there. Its backing
     file lives in the kubelet emptyDir directory, which is on `/home`, and
     it goes away with the pod. overlay2 on a guest-local filesystem works,
     and the result is per-pod, disk-backed and destroyed with the VM, which
     is exactly the acceptance criterion. This is the preferred option. It is
     **unverified on runtime-rs with cri-o**. The option is documented but
     newer than the virtio-fs path, and the `sizeLimit` and backing-file
     semantics must be checked in staging.
  2. **Loop-mounted sparse ext4 image** on a plain emptyDir (the Kata doc's
     second option): a wrapper in the dind container creates
     `/var/lib/docker.img` with a fixed size, then `mkfs.ext4` and
     `mount -o loop`. It needs `loop` in the guest kernel (present in Kata's
     guest kernel config per the doc) and a small entrypoint change. This is
     the fallback.
  3. `emptyDir: {medium: Memory}`: unacceptable for image builds. A backend
     build writes many GiB of layers, and that would come out of the VM's RAM.
- `docker:dind` declares `/var/lib/docker` as a `VOLUME`. With an explicit
  mount on that path the declaration is harmless. Without one, cri-o would
  create an anonymous volume, which is another virtio-fs share. Keep an
  explicit mount.
- The guest kernel has overlay and netfilter (the doc says the overlay module
  has been present since Kata 2.0), so dockerd's bridge and iptables
  networking work inside the guest. dockerd in `docker:dind` uses
  iptables-nft or iptables-legacy depending on what it detects; the smoke
  test must confirm that a container started by the nested dockerd reaches
  the registry mirror.

### Other volumes

- `work`, `dind-var`, `dind-externals` and `docker-config-dir` are emptyDirs
  shared between the runner and dind containers in the same pod, so both
  containers in the same guest see them. With `emptydir_mode = "shared-fs"`
  they are virtio-fs shares from the host. With `block-plain` they become
  guest-local block devices. Either works for sharing *within* the pod.
  `/var/run` (`dind-var`) carries the docker socket, and a unix socket on a
  guest-local filesystem is fine. On virtio-fs, a unix socket created by one
  container and connected to by another inside the same guest also works,
  because both are the same guest kernel's VFS. Even so, prefer `block-plain`
  for everything if it proves out.
- The ConfigMap `daemon.json` and the Secret are virtio-fs-shared read-only
  files. Fine.

### The hostPath buildkit cache

- `/home/runner-cache/buildkit` would be a virtio-fs share. Data reads and
  writes work. The **slot locking does not**: `flock()` on virtio-fs is
  resolved by each guest kernel. virtiofsd does not forward flock or POSIX
  locks to the host by default, and the Kata configs do not enable it.
  So two VMs would both "win" `slot-0.lock` and write the same cache index.
  This is inferred from virtiofsd's documented options; we did not find a
  Kata doc that states it directly.
- The cache is also a shared, *writable* directory across jobs. #6072 allows
  only "an explicit, read-mostly build cache".
- It is empty today (4.0 KiB), and the backend builds already use
  `cache-from/cache-to type=registry` on ghcr. Drop the buildkit hostPath
  from the Kata pool. Do not try to fix the locking.

### Memory sizing and the RuntimeClass overhead

How Kata sizes the VM (docs, `configuration-qemu-runtime-rs.toml`): the VM
boots with `default_memory` MiB (2048 by default) and `default_vcpus` (1).
Each container's memory and CPU **limits** are then hot-plugged into the
guest when the container is created. Memory is not unplugged when a container
exits, so the init containers' limits stay in the guest for the pod's life
(behaviour per the Kata hotplug design; verify in staging).

For today's docker pod spec under Kata:

| Part | Guest memory |
|---|---|
| base `default_memory` | 2 GiB (default) |
| 3 init containers at 1Gi limit each | up to 3 GiB |
| dind limit | 16 GiB |
| runner limit | 4 GiB |
| **guest size** | **up to 25 GiB** |

On the host side, the pod cgroup (with `sandbox_cgroup_only = true`, the
QEMU default) is limited to the sum of the container limits plus the
RuntimeClass `overhead`. If guest RAM can exceed that cgroup, a guest that
fills its page cache gets the whole VM OOM-killed by the host, rather than
having the guest kernel reclaim or kill a process inside the VM. So we
either size the guest no larger than the pod limit, or make the overhead
cover `default_memory`.

The scheduler and ResourceQuota add `RuntimeClass.overhead.podFixed` to
the pod's requests (PodOverhead, GA in 1.24; ResourceQuota counts it). In
kata-deploy 4.3.1 the default overhead for `qemu-runtime-rs` is 320Mi /
250m.

Settings proposed for the runner config:

- `default_memory = 1024`, `default_vcpus = 1`. The agent, guest kernel and
  systemd-free rootfs need well under 1 GiB.
- Lower the three init containers to a 128Mi limit in the Kata pool (they
  run `cp`, `chmod` and `sh`), and the runner container to a 2Gi limit (it
  only drives buildx and `docker save | gzip`, per the values file).
- Overhead `memory: 1536Mi` (1 GiB base plus about 320Mi for QEMU, virtiofsd
  and the shim, plus slack), `cpu: 500m`.

Guest size then becomes 1 + 0.375 + 16 + 2, about 19.4 GiB. The host-side
cgroup limit is 18.4 + 1.5, about 19.9 GiB.

**The budget problem:** under runc, memory a docker pod does not use is
memory the node has. The measured per-pod working set is p50 1.7 / p90 13.0 /
max 14.0 GiB, against a 6Gi request. Under Kata, guest page cache from layer
extraction and build output is RAM in the QEMU process. It stays charged to
the pod, and the host cannot reclaim it unless free-page reporting through
the balloon is enabled. So a Kata docker pod's real footprint trends to its
limit (about 19.9 GiB) for as long as the job runs, while the scheduler still
sees 6 + 1 + 1.5 = 8.5 GiB.

At the live `maxRunners: 6`, that is 6 x 19.9 = about 119 GiB of potential
real use from one pool. The budget in `budget/rocky.yaml` assumes 42 GiB for
everything outside the runners, out of 146.8 allocatable, and the release
gate does run 6 docker pods at once (observed). That arithmetic does not
close.

What the pilot must do about it:

1. Set the Kata docker pod's **requests equal to its limits** (dind 16Gi,
   runner 2Gi, init 128Mi), so the scheduler and `runner-pool-cap` see the
   real footprint: about 19.9 GiB per pod including overhead.
2. Cap the pool at `maxRunners: 2` for the pilot (about 40 GiB, comparable
   to the 42 GiB that 6 runc docker pods reserve today at 7 GiB each). The
   release gate's 6-way DTF fan-out then queues on this pool: either accept
   that for the pilot, or point the release gate at a separate runc pool
   first.
3. Teach the budget about overhead. `scripts/pool_budget.py` sums container
   requests from `helm template` and does not see RuntimeClass overhead. Add
   `extra_per_runner: {memory: 1536Mi, cpu: 500m}` to the ak-docker-runners
   entry in `budget/rocky.yaml`, which the script already supports, and keep
   it equal to the RuntimeClass.
4. Check whether runtime-rs 4.3.1's QEMU config exposes a free-page-reporting
   or balloon option (the Go runtime calls it `reclaim_guest_freed_memory`).
   If it does and works on this kernel, requests can come back down later.
   Do not count on it for the pilot.

CPU: vCPUs are `default_vcpus` plus the sum of CPU limits (1 + 12 + 2, plus
the init limits), so about 15 to 18 vCPU threads per VM. Under the CFS quota
of the pod cgroup this is fine. The CARGO_BUILD_JOBS note in the values file
still applies, because the guest reports its vCPU count to `nproc`, not 88,
which is an improvement.

### ARC values

ARC 0.13.1 passes `template.spec` through verbatim, so the only
runtime-specific field is `template.spec.runtimeClassName: kata`. The rest of
the diff is the storage and sizing changes above. See section 4.3.

## 4. Change plan (Kata), if it goes ahead

Do **not** run any of this on `rocky` until stage 0 has passed.

### 4.0 Stage 0: rehearse off-production (required)

`rocky` has nested KVM (`kvm_intel nested=1`). Build a throwaway Rocky 8.10
VM with libvirt on `rocky`, or anywhere: 8 vCPU, 32 GiB, the same kernel
stream, kubeadm 1.31, cri-o 1.31.5 from the same repo, cgroupfs, flannel.
Then run sections 4.1 to 4.4 there end to end, including a real backend
image build with the ak-docker pod spec.

Exit criteria:
- runtime-rs works on cgroup v1 with cgroupfs (or the Go runtime does, as
  the fallback).
- `block-plain` or the loop-mount option gives dind overlay2.
- `systemctl reload crio` picks up the handler without restarting anything.
- A pod OOM inside the guest stays inside the guest.

Nested timings understate real performance, so judge correctness, not
speed.

### 4.1 Install Kata (static tarball to /opt/kata)

```sh
# On rocky, as root, inside the maintenance window (see 4.6).
set -euo pipefail
VER=4.3.1
WORK=$(mktemp -d /home/kata-install.XXXXXX)   # /home has 1.1T free; / has 28G
cd "$WORK"

# 1. Fetch and verify against the GitHub asset digest (no checksum files are published).
#    Run the gh line on a workstation and paste the digest here.
#    gh api repos/kata-containers/kata-containers/releases/tags/$VER \
#      --jq '.assets[] | select(.name=="kata-static-'"$VER"'-amd64.tar.zst") | .digest'
EXPECTED=sha256:<paste>
curl -fL -o kata-static-$VER-amd64.tar.zst \
  https://github.com/kata-containers/kata-containers/releases/download/$VER/kata-static-$VER-amd64.tar.zst
echo "${EXPECTED#sha256:}  kata-static-$VER-amd64.tar.zst" | sha256sum -c -

# 2. Check the size first; it must fit on / (28G free today).
zstd -dc kata-static-$VER-amd64.tar.zst | tar -tvf - | awk '{s+=$3} END {print s/1024/1024/1024 " GiB"}'

# 3. Extract (el8 tar 1.30 has no --zstd; pipe through zstd). The tarball's paths are opt/kata/...
test ! -e /opt/kata
zstd -dc kata-static-$VER-amd64.tar.zst | tar -xf - -C /
ls -l /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 \
      /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml

# 4. Host modules: load now and at boot (both are idempotent, and nothing running uses them).
cat > /etc/modules-load.d/kata.conf <<'EOF'
vhost
vhost_net
vhost_vsock
EOF
modprobe -a vhost vhost_net vhost_vsock

# 5. Our own config copy; never edit the files under /opt/kata.
install -d -m 0755 /etc/kata-containers/ak
cp /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml \
   /etc/kata-containers/ak/configuration-qemu-runtime-rs.toml
```

Edit `/etc/kata-containers/ak/configuration-qemu-runtime-rs.toml`, keeping
the shipped paths for the kernel, image, QEMU and virtiofsd:

```toml
[hypervisor.qemu]
default_vcpus = 1
default_memory = 1024
# default_maxmemory: leave at 0 (host RAM); the pod cgroup is the real cap.

[runtime]
sandbox_cgroup_only = true
emptydir_mode = "block-plain"     # stage 0 decides; fallback "shared-fs" plus the loop-mount entrypoint
enable_debug = false
```

Then run the host check from the tools tarball (`kata-tools-static-4.3.1`
contains `kata-ctl`), extracted the same way into a scratch directory, not
into /opt/kata:

```sh
./opt/kata/bin/kata-ctl check     # path inside the tools tarball; confirm at stage 0
```

### 4.2 cri-o drop-in and reload

`/etc/crio/crio.conf.d/50-kata.conf`. It mirrors what kata-deploy 4.3.1
writes, minus its `[crio] storage_option = ["overlay.skip_mount_home=true"]`
line. That line changes storage for **every** container, and storage options
are not reloadable.

```toml
[crio.runtime.runtimes.kata]
runtime_path = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
runtime_type = "vm"
runtime_root = "/run/vc"
runtime_config_path = "/etc/kata-containers/ak/configuration-qemu-runtime-rs.toml"
privileged_without_host_devices = true
```

The file sorts after `10-*.conf` and does not touch `default_runtime`, runc
or crun.

```sh
install -m 0644 50-kata.conf /etc/crio/crio.conf.d/50-kata.conf
systemctl reload crio            # SIGHUP. NOT restart.
journalctl -u crio --since -2min --no-pager | grep -E 'Reloading configuration|Updating runtime configuration|unable|error'
kubectl get node rocky -o jsonpath='{.status.runtimeHandlers[*].name}'; echo    # expect kata in the list within ~1 min
```

**Why a reload is enough (from the source):** in cri-o v1.31.5,
`pkg/config/reload.go` re-reads `crio.conf` and the drop-in directory on
SIGHUP. Its `ReloadRuntimes` replaces the runtimes table when it changed and
validates it. The same reload also re-applies log level, pause image, pinned
images, registries, seccomp, AppArmor, blockio, RDT and the CDI directories
from the same unchanged files, so it is a no-op for those. The live config
already matches what the files produce (checked via the socket's `/config`).

If reload validation fails, the old runtimes stay in place. Confirm at stage
0 that a failed reload leaves cri-o serving.

**If a restart were ever needed** (storage options, a cri-o upgrade, or a
reload that does not take): on this host, treat a cri-o restart as a
full-node outage, not as zero-downtime.
- Observed: the unit has `KillMode=control-group`, and every conmon (97 at
  survey time) is in `crio.service`'s `name=systemd`, `memory`, `pids` and
  `devices` cgroups. `systemctl restart crio` therefore SIGTERMs, then
  SIGKILLs after 90 s, every conmon on the node: production, nexus, argocd,
  keycloak, monitoring, etcd and the apiserver's.
- The containers themselves are in kubepods cgroups and are not signalled
  directly. But they lose their conmon (stdio pipes, log writer, exit-code
  capture), and what happens next depends on each process's handling of
  EPIPE/SIGPIPE on stdout and stderr. We have not tested it here; assume
  every pod restarts.
- The usual mitigation is a unit drop-in with `KillMode=mixed` or
  `KillMode=process` for crio.service, applied with `systemctl daemon-reload`
  before any restart. Validate it at stage 0. It is out of scope for this
  plan and needs its own window and its own review.

### 4.3 RuntimeClass and the ARC diff for ak-docker-runners

`cluster/runtimeclass-kata.yaml` (new, in artifact-keeper-arc-runners):

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
  labels:
    app.kubernetes.io/part-of: ak-infra
handler: kata          # must equal the [crio.runtime.runtimes.kata] table name
overhead:
  podFixed:
    # default_memory 1024 MiB + ~320 MiB QEMU/virtiofsd/shim + slack.
    # Keep equal to budget/rocky.yaml ak-docker-runners.extra_per_runner.
    memory: 1536Mi
    cpu: 500m
```

There is one node, so `scheduling` is not needed. Add a `nodeSelector` on a
`katacontainers.io/kata-runtime=true` label only if a second node appears.

Diff to `argocd/arc-docker-runners-values.yaml`. The base is the live values
(maxRunners 6), not git (2); reconcile that drift in a separate PR first.

```diff
-maxRunners: 6
+# Kata pilot: each pod's real footprint is ~19.9 GiB (requests = limits +
+# RuntimeClass overhead), see docs/ci/kata-runtimeclass-plan.md.
+maxRunners: 2

 template:
   spec:
+    runtimeClassName: kata
     priorityClassName: ak-runner-docker
@@ runner container
-        command: [ ... flock slot loop ... exec /home/runner/run.sh ]
+        command: ["/home/runner/run.sh"]       # no persistent buildkit slot under Kata
         resources:
           requests:
             cpu: 500m
-            memory: 1Gi
+            memory: 2Gi
           limits:
             cpu: "2"
-            memory: 4Gi
+            memory: 2Gi
         volumeMounts:
@@
-          - name: buildkit-cache
-            mountPath: /cache/buildkit
@@ initContainers: init-dockerhub-creds, init-dind-externals
           limits:
             cpu: "1"
-            memory: 1Gi
+            memory: 128Mi
-      - name: init-buildkit-cache
-        ...                                    # removed with the hostPath
@@ dind
         resources:
           requests:
             cpu: "2"
-            memory: 6Gi
+            memory: 16Gi                       # = limit: guest RAM is not returned to the host
           limits:
             cpu: "12"
             memory: 16Gi
         volumeMounts:
-          - name: dind-docker
-            mountPath: /var/lib/docker
-            subPathExpr: $(POD_NAME)
+          - name: dind-docker
+            mountPath: /var/lib/docker
     volumes:
-      - name: dind-docker
-        hostPath:
-          path: /home/runner-dind
-          type: DirectoryOrCreate
+      # With emptydir_mode=block-plain, a guest-local block device: overlay2
+      # works, and it dies with the VM. No runner-dind-cleanup needed for this pool.
+      - name: dind-docker
+        emptyDir:
+          sizeLimit: 200Gi
-      - name: buildkit-cache
-        hostPath:
-          path: /home/runner-cache/buildkit
-          type: DirectoryOrCreate
```

Also in the same PR:
- `budget/rocky.yaml`: give `ak-docker-runners` an
  `extra_per_runner: {memory: 1536Mi, cpu: 500m}`, and run
  `scripts/pool_budget.py check` to confirm the quota still closes.
- The docker workflows that read `AK_BUILDKIT_CACHE_DIR` must tolerate it
  being unset. They already warn and continue, because nothing uses it yet.

Apply order (scripts/apply.sh rolls one pool and waits for the old
EphemeralRunnerSet to drain):

```sh
kubectl apply -f cluster/runtimeclass-kata.yaml
helm upgrade ak-docker-runners -n arc-runners --version 0.13.1 \
  -f argocd/arc-docker-runners-values.yaml \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

### 4.4 Verification

1. A smoke pod in a scratch namespace, before touching ARC:
   ```sh
   kubectl create ns kata-smoke
   kubectl -n kata-smoke run k --image=busybox:1.36.1 --restart=Never \
     --overrides='{"spec":{"runtimeClassName":"kata"}}' -- uname -r
   kubectl -n kata-smoke logs k        # must NOT print 4.18.0-553...; expect the Kata guest kernel (6.x)
   pgrep -af 'qemu.*sandbox-'          # on rocky: one QEMU per Kata pod
   ```
2. A dind smoke pod with the exact ak-docker volumes and the dind container:
   check `docker info` (Storage Driver: overlay2, Backing Filesystem: extfs,
   not vfs), `docker run --rm busybox wget -qO- <registry mirror>`, a
   `docker buildx build` of a small Dockerfile, then delete the pod and
   confirm that no QEMU process remains and the emptyDir directory under
   `/var/lib/kubelet/pods/<uid>` is gone.
3. Memory: in the smoke pod, run `stress-ng --vm 1 --vm-bytes 18G` in dind
   and confirm the guest OOM-kills inside the VM, with nothing in the host
   `dmesg` against the QEMU process. Also write 30 GiB of files and watch
   the QEMU RSS on the host (`ps -o rss`), to see where page cache lands.
4. ARC: dispatch the existing `zz diag docker runner limits` workflow, then
   one `ci.yml` "Build Backend Image" run. On rocky, check
   `kubectl -n arc-runners get pod -l actions.github.com/scale-set-name=ak-docker-runners -o jsonpath='{.items[*].spec.runtimeClassName}'`
   (all `kata`), check `crictl ps` (the dind container's runtime is the Kata
   handler), and confirm that no host mount of `/var/lib/docker` exists for
   these pods (`findmnt | grep runner-dind` shows nothing new).
5. Release path, per #6072: one Docker Publish run on a test tag in a fork,
   or with `workflow_dispatch` against a throwaway image name. Confirm that
   the cosign signature, SBOM attestation and provenance verify exactly as
   before (`cosign verify`, `cosign verify-attestation`,
   `gh attestation verify`).
6. For 48 hours, watch node memory (`kubectl top node`, the
   kube-prom alerts), arc-pool-guard waits, and evictions in
   artifact-keeper-prod.

### 4.5 Rollback

Roll back in reverse order. Each step is safe on its own.

```sh
# 1. ARC back to runc (the previous helm revision, or a git revert of the values PR plus apply.sh).
helm -n arc-runners history ak-docker-runners | tail -3
helm -n arc-runners rollback ak-docker-runners <previous-revision>
# Wait until no pod uses the class:
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.runtimeClassName=="kata")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
pgrep -af 'qemu.*sandbox-' || echo "no kata VMs"

# 2. The RuntimeClass.
kubectl delete runtimeclass kata
kubectl delete ns kata-smoke --ignore-not-found

# 3. The cri-o handler (reload, not restart).
rm -f /etc/crio/crio.conf.d/50-kata.conf
systemctl reload crio
journalctl -u crio --since -2min --no-pager | grep -E 'Updating runtime configuration|error'
kubectl get node rocky -o jsonpath='{.status.runtimeHandlers[*].name}'; echo    # kata gone

# 4. Files and modules.
rm -rf /etc/kata-containers/ak /opt/kata
rm -f /etc/modules-load.d/kata.conf
modprobe -r vhost_vsock vhost_net 2>/dev/null || true    # optional; a no-op if in use
```

If a Kata pod is stuck terminating after step 1, its QEMU can be killed by
PID after `crictl stopp <pod-id>`. Never kill conmon or cri-o.

### 4.6 Maintenance window rule

Run step 4.2 (cri-o reload) and step 4.3 (the ARC change) only when **all**
of the following hold, checked right before starting:

```sh
# No Release Candidate or Docker Publish run in progress or queued.
for wf in "Release Candidate" "Docker Publish"; do
  for st in in_progress queued; do
    gh run list -R artifact-keeper/artifact-keeper --workflow "$wf" --status "$st" \
      --json databaseId,displayTitle,createdAt --jq '.[] | "\(.databaseId) \(.displayTitle)"'
  done
done
# The release gate runs on ak-docker-runners too.
gh run list -R artifact-keeper/artifact-keeper-test --workflow release-gate.yml --status in_progress \
  --json databaseId,displayTitle --jq '.[] | "\(.databaseId) \(.displayTitle)"'
# All of the above must print nothing.

# No ARC runner busy (every EphemeralRunner idle, with no job assigned).
ssh khan@rocky "kubectl -n arc-runners get ephemeralrunners \
  -o jsonpath='{range .items[*]}{.metadata.name}{\"\t\"}{.status.jobDisplayName}{\"\n\"}{end}'" \
  | awk -F'\t' '\$2 != ""'
# Must print nothing.
```

Also: no release prep PR is about to merge, and nothing is happening on
artifact-keeper-prod (announce in the ops channel). If anything appears
mid-window, stop before the next step. The reload is quick, but the ARC
rollout recreates the docker pool.

## 5. The alternative: a libvirt/KVM ephemeral-VM runner service (`ak-vm`)

> As built: [`vm-runners.md`](vm-runners.md) documents the service that
> implements this alternative (`scripts/ci/vm-runner/`). It differs from the
> sketch below in three places. It keeps a small pool of idle VMs instead of
> scaling on queued jobs. It puts the VMs on a dedicated libvirt network,
> `ak-vm`, with a per-interface nwfilter instead of nftables rules on
> virbr0, and does not use the in-cluster registry mirror, since the filter
> blocks the cluster. It caps the VMs with `machine-akvm.slice`. The budget
> carve-out in artifact-keeper-arc-runners is still to do.

This is a small host service, outside Kubernetes. On a queued job with label
`ak-vm`, it:

1. creates a qcow2 overlay on a read-only base image;
2. boots one VM through libvirt (host qemu-kvm 6.2 and libvirt 8.0, both
   already installed);
3. injects a one-time JIT runner config
   (`POST /orgs/{org}/actions/runners/generate-jitconfig`) through cloud-init
   or a virtio-serial channel;
4. lets the runner take exactly one job;
5. destroys the domain and deletes the overlay.

No cri-o change and no Kubernetes object.

| | Kata RuntimeClass | libvirt `ak-vm` |
|---|---|---|
| Isolation | Per-pod VM, own kernel; host-side root QEMU, shim and virtiofsd | Per-job VM, own kernel; root or `qemu` user QEMU from the el8 module; no virtiofsd unless we add one |
| Change on the production node | New cri-o runtime handler (reload); a cri-o restart is a full-node outage here | None to cri-o or kubelet; a new systemd service and libvirt network |
| dockerd storage | Needs `block-plain` (unverified on runtime-rs/cri-o) or a loop-mount hack | Native: overlay2 on the VM's own ext4/xfs disk |
| Build cache | hostPath slots must go (flock is broken across guests); registry cache only | Registry cache; optionally a read-only cache disk attached to every VM, which matches #6072's "read-mostly" wording |
| Memory accounting | Inside the k8s budget, but real use is about the limit; requests must equal limits; needs an overhead entry in the budget | Outside the scheduler. Must be carved out explicitly: raise `systemReserved` (or set a dedicated `ak-vm.slice` with `MemoryMax` and shrink `runner-pool-cap` by the same amount), and update `budget/rocky.yaml` `reserved` |
| Autoscaling | ARC as today; workflows unchanged | Our own scaler (poll queued `workflow_job`s, or a webhook); workflows change `runs-on` to `ak-vm` |
| Upstream fit | Kata 4.x, runtime-rs default, little testing on EL8 4.18 + cgroup v1 + cri-o; monthly releases to track | Stock EL8 virt stack, supported by the distribution, nothing new to track |
| Code we own | Values and config only | A service (scaler, VM lifecycle, image pipeline, cleanup), the GitHub App or token with runner-admin scope, monitoring |
| Contributor docs (#6072 acceptance) | "Install Kata on your cluster": heavy for contributors | "Run this service on any KVM host": simpler to reproduce off-k8s |
| Second step for the other pools | Same RuntimeClass, but each pool hits the same memory problem | Same service with more labels; or Kata later on EL9/cgroup v2 |

Risks of `ak-vm`:
- **Capacity outside the scheduler.** If the VM service and the ARC pools are
  sized independently, both can fill the node, and the kubelet only evicts
  pods. Production pods are pods, and the VMs are not. The carve-out (a
  dedicated slice with a hard `MemoryMax`, `systemReserved` raised to match,
  and `runner-pool-cap` lowered) must land before the first VM, and the
  budget check should learn the new number.
- **Credential handling.** The service holds a credential that can mint JIT
  runner configs for the org. Scope it to a dedicated runner group that only
  the release repositories can use. Keep the credential out of the VM (inject
  only the JIT config, which is single-use).
- **Image upkeep.** The base image (runner version, docker, buildx, cosign)
  is ours to rebuild. Tie it to the existing `runner-images.yml` and
  `runner-version-check.yml` cadence.
- **Network.** VMs on virbr0 NAT reach ghcr and Docker Hub through the
  registry mirror. They must not reach the cluster's pod or service CIDRs or
  the host's sshd and kubelet. Add explicit nftables rules on virbr0.
- **Signing and provenance** do not change, because the same workflow steps
  run with the same OIDC token. Only `runs-on` changes for the Docker Publish
  jobs.

## 6. Recommendation

1. **Ship `ak-vm` for Docker Publish first** (the issue's own ordering). It
   meets every #6072 acceptance item without changing the runtime of a node
   that hosts production. Land the memory carve-out and the budget update in
   the same PR set as the service.
2. **Do not enable Kata on rocky now.** The blockers are, in order:
   - dind storage (`/var/lib/docker` on hostPath, and overlay on virtio-fs);
   - the memory model (VM RAM follows limits and is not returned to the
     host, against a requests-based budget with a 6-way release-gate
     fan-out);
   - the untested runtime-rs + cgroup v1 + cri-o + EL8 4.18 combination;
   - the full-node blast radius of any cri-o restart (`KillMode=control-group`
     with conmon in `crio.service`).
3. **Keep this plan as the Kata path for later.** Run stage 0 in a nested VM
   when there is time. Revisit when rocky moves to EL9 and cgroup v2 (needed
   before Kubernetes 1.35 anyway). At that point, also fix the cri-o unit's
   KillMode so a cri-o restart stops being a node outage.
4. Independent of the choice, two drifts are worth a small PR:
   - `ak-docker-runners` runs at `maxRunners: 6` live, but git says 2;
   - the buildkit cache slots are unused (4.0 KiB), and the workflows never
     consumed them.

## Sources

Observed on rocky (read-only, 2026-11-16): `rpm -q`, `lsmod`, `modinfo -n`,
`/proc/<pid>/cgroup`, `systemctl cat/show/status crio`, `/etc/crio/crio.conf.d/*`,
a GET of `/config` on the cri-o socket, `/var/lib/kubelet/config.yaml`,
`kubectl get node/pods/autoscalingrunnersets/ephemeralrunners/resourcequota/pc`,
`helm get values`, `virsh list/net-list`.

Repository: artifact-keeper/artifact-keeper-arc-runners `argocd/arc-docker-runners-values.yaml`,
`budget/rocky.yaml`, `cluster/arc-runners-quota.yaml` (default branch).

Upstream:
- Kata releases: https://github.com/kata-containers/kata-containers/releases (4.3.1, 4.0.0 notes)
- kata-deploy 4.3.1 cri-o drop-in: `tools/packaging/kata-deploy/binary/src/runtime/crio.rs`; paths: `binary/src/utils/system.rs`; RuntimeClass overhead defaults: `helm-chart/kata-deploy/templates/runtimeclasses.yaml`
- Docker in Kata: https://github.com/kata-containers/kata-containers/blob/4.3.1/docs/how-to/how-to-run-docker-with-kata.md
- Kata QEMU configs: `src/runtime/config/configuration-qemu.toml.in`, `src/runtime-rs/config/configuration-qemu-runtime-rs.toml.in` (`emptydir_mode`, `default_memory`, `sandbox_cgroup_only`)
- cri-o 1.31.5 SIGHUP reload: https://github.com/cri-o/cri-o/blob/v1.31.5/pkg/config/reload.go (`ReloadRuntimes`)
- Kubernetes cgroup v1 deprecation and the 1.35 `failCgroupV1` default: https://kubernetes.io/blog/2026/10/06/kubernetes-cgroups-v2-shift/
