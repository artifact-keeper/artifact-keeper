#!/usr/bin/env bash
#
# Runs ONCE inside the image-build VM (cloud-init runcmd), then powers off.
# ak-vm-runner build-image turns the powered-off disk into the next golden
# image only if this script printed AKVM-IMAGE-OK on the serial console.
#
# @RUNNER_VERSION@ and @RUNNER_SHA256@ are filled in by ak-vm-runner.
set -euo pipefail
exec > >(tee -a /dev/ttyS0) 2>&1
trap 'echo "AKVM-IMAGE-FAIL line=$LINENO"; sync; systemctl poweroff' ERR

RUNNER_VERSION="@RUNNER_VERSION@"
RUNNER_SHA256="@RUNNER_SHA256@"
export DEBIAN_FRONTEND=noninteractive

# Nothing may compete with a job for the dpkg lock or rewrite packages under it.
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service || true
systemctl mask apt-daily.service apt-daily-upgrade.service unattended-upgrades.service || true
# No inbound shell: the only interface to a job VM is the serial console log.
systemctl disable --now ssh.socket ssh.service || true
systemctl mask ssh.service ssh.socket || true
# No IPv6 in a job VM: the ak-vm network has none, and the host filter is
# IPv4-first. Set on the kernel command line, so a job cannot undo it for
# the next job (a reboot destroys the VM anyway).
# shellcheck disable=SC2016 # literal: grub expands it
printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT ipv6.disable=1"\n' > /etc/default/grub.d/90-ak-vm.cfg
update-grub
# Keep the serial console for the kernel and the AKVM records: no login prompt.
systemctl mask serial-getty@ttyS0.service || true

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git jq unzip zip xz-utils \
  zstd gnupg rsync wget python3 python3-venv build-essential pkg-config libssl-dev

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker runner

# GitHub CLI, as on GitHub-hosted runners (workflows call `gh attestation
# verify`, `gh api`, ...). From GitHub's signed apt repository.
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
chmod a+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  > /etc/apt/sources.list.d/github-cli.list
apt-get update
apt-get install -y gh
systemctl enable docker.service containerd.service
systemctl restart docker.service

mkdir -p /opt/actions-runner
curl -fsSL -o /tmp/runner.tgz \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
echo "${RUNNER_SHA256}  /tmp/runner.tgz" | sha256sum -c -
tar -xzf /tmp/runner.tgz -C /opt/actions-runner
rm -f /tmp/runner.tgz
/opt/actions-runner/bin/installdependencies.sh
chown -R runner:runner /opt/actions-runner

# docker/setup-buildx-action starts this image for its docker-container
# builder; baking it in saves a pull on every job.
docker pull moby/buildkit:buildx-stable-1

systemctl daemon-reload

echo "AKVM-IMAGE-MANIFEST ubuntu=$(. /etc/os-release && echo "$VERSION_ID") kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' | sed 's/^vmlinuz-//' | sort -V | tail -n1) runner=${RUNNER_VERSION} docker=$(docker version --format '{{.Server.Version}}') buildx=$(docker buildx version | awk '{print $2}') gh=$(gh --version | awk 'NR==1 {print $3}') buildkit=$(docker image inspect moby/buildkit:buildx-stable-1 --format '{{index .RepoDigests 0}}')"

# Make the next boot a first boot for cloud-init, with fresh identities.
apt-get clean
rm -rf /var/lib/apt/lists/* /var/log/cloud-init*.log /root/.bash_history
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*
fstrim -av || true
sync
echo "AKVM-IMAGE-OK"
systemctl poweroff
