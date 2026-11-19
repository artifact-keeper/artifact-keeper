#!/usr/bin/env bash
#
# Installs ak-vm-runner on a libvirt/KVM host (#6072). Idempotent; run as
# root from a checkout:   sudo scripts/ci/vm-runner/install.sh
#
# It creates: the akvm system user (in the libvirt group), /opt/ak-vm-runner
# (code, root-owned), /etc/ak-vm-runner (config), /home/ak-vm-runner
# (images, VM disks, logs), the libvirt network ak-vm and nwfilter
# ak-vm-egress, machine-akvm.slice and the systemd units. It does NOT touch
# any existing libvirt network, container runtime, kubelet or firewall
# configuration, and it does not start the controller or write the token.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE=/home/ak-vm-runner
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for b in virsh qemu-img genisoimage jq curl flock; do
  command -v "$b" > /dev/null || { echo "missing $b" >&2; exit 1; }
done

getent group akvm > /dev/null || groupadd --system akvm
id akvm > /dev/null 2>&1 || useradd --system --gid akvm --home-dir "$STATE" --no-create-home \
  --shell /sbin/nologin --comment "ak-vm-runner (artifact-keeper#6072)" akvm
usermod -aG libvirt akvm

install -d -m 0755 -o root -g root /opt/ak-vm-runner /opt/ak-vm-runner/guest
install -m 0755 "$SRC/ak-vm-runner" /opt/ak-vm-runner/ak-vm-runner
install -m 0644 "$SRC"/guest/* /opt/ak-vm-runner/guest/
chmod 0755 /opt/ak-vm-runner/guest/*.sh

# Operator entry point: runs a subcommand as akvm with the config loaded.
cat > /usr/local/sbin/ak-vm-runner << 'WRAP'
#!/usr/bin/env bash
# ak-vm-runner operator wrapper (installed by scripts/ci/vm-runner/install.sh)
exec runuser -u akvm -- bash -c 'set -a; . /etc/ak-vm-runner/config.env; set +a; exec /opt/ak-vm-runner/ak-vm-runner "$@"' ak-vm-runner "$@"
WRAP
chmod 0750 /usr/local/sbin/ak-vm-runner

install -d -m 0750 -o root -g akvm /etc/ak-vm-runner
[[ -e /etc/ak-vm-runner/config.env ]] || install -m 0640 -o root -g akvm "$SRC/config.env.example" /etc/ak-vm-runner/config.env

# qemu (uid qemu) must traverse to the disks and console logs.
install -d -m 0711 -o akvm -g akvm "$STATE" "$STATE/vms" "$STATE/images"
install -d -m 0755 -o akvm -g akvm "$STATE/images/base" "$STATE/images/golden"
install -d -m 0750 -o akvm -g akvm "$STATE/log"
install -d -m 0711 -o akvm -g akvm "$STATE/log/console"
if [[ ! -e "$STATE/log/audit.jsonl" ]]; then
  install -m 0640 -o akvm -g akvm /dev/null "$STATE/log/audit.jsonl"
fi
# Append-only: the service user can add audit lines but not rewrite them.
chattr +a "$STATE/log/audit.jsonl" 2> /dev/null || echo "note: chattr +a not supported here" >&2

if ! virsh -q net-info ak-vm > /dev/null 2>&1; then
  virsh -q net-define "$SRC/libvirt/network.xml"
fi
virsh -q net-autostart ak-vm
virsh -q net-info ak-vm | grep -q '^Active: *yes' || virsh -q net-start ak-vm
# Redefining an existing filter needs its uuid; libvirt re-applies a
# changed filter to running VMs at once.
uuid="$(virsh -q nwfilter-dumpxml ak-vm-egress 2> /dev/null | sed -n 's|.*<uuid>\(.*\)</uuid>.*|\1|p')"
if [[ -n "$uuid" ]]; then
  sed "s|<filter name='ak-vm-egress' chain='root'>|&<uuid>$uuid</uuid>|" "$SRC/libvirt/nwfilter.xml" > "/run/ak-vm-egress.xml"
  virsh -q nwfilter-define /run/ak-vm-egress.xml
  rm -f /run/ak-vm-egress.xml
else
  virsh -q nwfilter-define "$SRC/libvirt/nwfilter.xml"
fi

install -m 0644 "$SRC"/systemd/ak-vm-runner.service "$SRC"/systemd/ak-vm-runner-image.service \
  "$SRC"/systemd/ak-vm-runner-image.timer "$SRC"/systemd/machine-akvm.slice /etc/systemd/system/
systemctl daemon-reload
systemctl start machine-akvm.slice
# Apply the slice's limits to the running slice too (never restart it: that
# would stop every VM in it).
limit="$(sed -n 's/^MemoryLimit=//p' "$SRC/systemd/machine-akvm.slice")"
quota="$(sed -n 's/^CPUQuota=//p' "$SRC/systemd/machine-akvm.slice")"
systemctl set-property --runtime machine-akvm.slice "MemoryLimit=$limit" "CPUQuota=$quota"

cat << MSG
Installed. Next:
  1. Write the token:  install -m 0640 -o root -g akvm /dev/stdin /etc/ak-vm-runner/github-token
  2. Build the image:  systemctl start ak-vm-runner-image.service   (10-20 min)
  3. Start the pool:   systemctl enable --now ak-vm-runner.service
  Optional weekly rebuild: systemctl enable --now ak-vm-runner-image.timer
MSG
