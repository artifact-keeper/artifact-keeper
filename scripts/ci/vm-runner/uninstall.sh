#!/usr/bin/env bash
#
# Removes ak-vm-runner (#6072): destroys every job VM (and its GitHub runner
# registration), stops and removes the units, the libvirt network ak-vm and
# nwfilter ak-vm-egress, the code and config. Keeps /home/ak-vm-runner
# (images, audit log) unless --purge is given.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
PURGE="${1:-}"

systemctl disable --now ak-vm-runner-image.timer 2> /dev/null || true
systemctl stop ak-vm-runner.service ak-vm-runner-image.service 2> /dev/null || true
systemctl disable ak-vm-runner.service 2> /dev/null || true
if [[ -x /opt/ak-vm-runner/ak-vm-runner && -r /etc/ak-vm-runner/config.env ]]; then
  runuser -u akvm -- bash -c 'set -a; . /etc/ak-vm-runner/config.env; set +a; /opt/ak-vm-runner/ak-vm-runner destroy-all' || true
fi
# Anything left with our prefixes (e.g. an image build VM).
for d in $(virsh -q list --all --name | grep -E "^akvm-($(hostname -s)-|image-)" || true); do
  virsh -q destroy "$d" > /dev/null 2>&1 || true
  virsh -q undefine "$d" > /dev/null 2>&1 || true
done
virsh -q net-destroy ak-vm 2> /dev/null || true
virsh -q net-undefine ak-vm 2> /dev/null || true
virsh -q nwfilter-undefine ak-vm-egress 2> /dev/null || true
rm -f /etc/systemd/system/ak-vm-runner.service /etc/systemd/system/ak-vm-runner-image.service \
  /etc/systemd/system/ak-vm-runner-image.timer /etc/systemd/system/machine-akvm.slice
systemctl daemon-reload
rm -rf /opt/ak-vm-runner /etc/ak-vm-runner /usr/local/sbin/ak-vm-runner
if [[ "$PURGE" == --purge ]]; then
  chattr -a /home/ak-vm-runner/log/audit.jsonl 2> /dev/null || true
  rm -rf /home/ak-vm-runner
  userdel akvm 2> /dev/null || true
  groupdel akvm 2> /dev/null || true
fi
echo "ak-vm-runner removed${PURGE:+ (purged)}"
