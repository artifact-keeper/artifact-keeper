#!/usr/bin/env bash
#
# ak-vm-job.service: run exactly one GitHub Actions job, then power off.
# The host destroys the VM and deletes its disk once it is off.
#
# Every line that starts with "AKVM " on the serial console is read by the
# host controller (ak-vm-runner) for its audit log.
set -uo pipefail

say() { printf '\r\nAKVM %s\r\n' "$*" > /dev/ttyS0; }
stop() {
  sync
  systemctl poweroff
  exit "${1:-0}"
}

JIT_FILE=/etc/ak-vm/jitconfig
if [[ ! -s "$JIT_FILE" ]]; then
  say "event=guest_error reason=no_jitconfig"
  stop 1
fi
jit="$(cat "$JIT_FILE")"
rm -f "$JIT_FILE"
# Open the tray on the seed ISO; the host then removes the medium for good.
eject /dev/sr0 > /dev/null 2>&1 || true

for _ in $(seq 1 120); do
  docker info > /dev/null 2>&1 && break
  sleep 1
done
if ! docker info > /dev/null 2>&1; then
  say "event=guest_error reason=docker_not_ready"
  stop 1
fi

# The job hooks log with tag akvm-job; forward those lines to the console.
journalctl -f -n0 -o cat -t akvm-job > /dev/ttyS0 2>&1 &

say "event=runner_start kernel=$(uname -r) docker=$(docker version --format '{{.Server.Version}}' 2> /dev/null)"
cd /opt/actions-runner || stop 1
runuser -u runner -- env -i HOME=/home/runner USER=runner LOGNAME=runner LANG=C.UTF-8 \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/ak-vm/job-started.sh \
  ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/libexec/ak-vm/job-completed.sh \
  ./run.sh --jitconfig "$jit"
rc=$?
jit=""
sleep 2
say "event=runner_exit code=$rc"
stop 0
