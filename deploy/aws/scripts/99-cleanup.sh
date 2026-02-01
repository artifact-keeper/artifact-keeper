#!/usr/bin/env bash
set -euo pipefail

echo "==> [99] Cleaning up for AMI snapshot"

# Clean apt cache
apt-get clean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*

# Remove temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear logs for clean start
journalctl --rotate
journalctl --vacuum-time=1s
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.gz" -delete

# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Remove machine-id (regenerated on first boot)
truncate -s 0 /etc/machine-id

# Remove packer scripts
rm -rf /tmp/ak-scripts

# Clear bash history
unset HISTFILE
rm -f /root/.bash_history
rm -f /home/ubuntu/.bash_history

echo "==> [99] Cleanup complete — ready for snapshot"
