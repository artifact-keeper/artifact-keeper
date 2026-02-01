#!/usr/bin/env bash
set -euo pipefail

echo "==> [99] Cleaning up for AMI snapshot"

apt-get clean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
rm -rf /tmp/*
rm -rf /var/tmp/*

journalctl --rotate
journalctl --vacuum-time=1s
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.gz" -delete

rm -f /etc/ssh/ssh_host_*
truncate -s 0 /etc/machine-id

unset HISTFILE
rm -f /root/.bash_history
rm -f /home/ubuntu/.bash_history

echo "==> [99] Cleanup complete — ready for snapshot"
