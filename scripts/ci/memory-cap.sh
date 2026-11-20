#!/usr/bin/env bash
#
# Run one compile in a memory cgroup whose memory.high leaves RAM for the
# rest of the hosted VM (#6242).
#
# WHY THIS EXISTS
#   The backend crate's own rustc no longer fits a 16 GB GitHub-hosted
#   runner. Measured in a 16 GiB, 4-CPU, no-swap container with CI's flags
#   (PR for #6242, Validation section): the instrumented handlers-1 lib-test
#   rustc needs 18.2 GiB and is OOM-killed at 16; the `ci`-profile lib in the
#   image build needs 17.2 GiB. The peak is in the front end and the
#   monomorphization collector, BEFORE any LLVM work, so CARGO_BUILD_JOBS,
#   codegen-units, debuginfo and the linker do not move it.
#
#   The jobs add a swapfile, so the build can finish, but nothing decides
#   WHOSE pages go to swap. Under global reclaim the kernel takes them from
#   everything: the runner agent, dockerd, the executables' page cache. The
#   agent then stops answering ("The hosted runner lost communication with
#   the server", "received a shutdown signal"), and a stalled Check Rust ran
#   past both its 30-minute `timeout` and the 45-minute job ceiling, because
#   nothing on the VM could run any more.
#
#   memory.high on a cgroup that holds only the compile makes the kernel
#   reclaim from the compile first, once it passes the limit: its cold pages
#   go to swap and it slows down, while the agent, Postgres and dockerd keep
#   their memory. It is a throttle, not a kill (memory.max is left alone).
#
# USAGE
#   memory-cap.sh [--reserve-mib N] [--] <command> [args...]
#
#   memory.high = MemTotal - N MiB (default 2816, i.e. 2.75 GiB left for the
#   OS, the runner agent, dockerd, Postgres and zram's compressed pages).
#   Exits with the command's status. Best effort: if the cgroup cannot be
#   set up (no cgroup v2, no memory controller, no passwordless sudo) it
#   prints a ::warning:: and runs the command uncapped, so it can never turn
#   a job red on its own. After the command it prints the cgroup's
#   memory.peak and how often the limit throttled it (memory.events "high").
#
# Env (tests): MEMCAP_CGROUP_ROOT (default /sys/fs/cgroup), MEMCAP_MEMINFO
# (default /proc/meminfo), MEMCAP_SUDO (default "sudo -n"; empty runs the
# writes directly), MEMCAP_NAME (default ak-ci-memcap-<pid>).
set -uo pipefail

reserve_mib=2816
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reserve-mib)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "memory-cap: --reserve-mib needs a number of MiB" >&2; exit 2; }
      reserve_mib="$2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "memory-cap: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
if [[ $# -eq 0 ]]; then
  echo "usage: memory-cap.sh [--reserve-mib N] [--] <command> [args...]" >&2
  exit 2
fi

root="${MEMCAP_CGROUP_ROOT:-/sys/fs/cgroup}"
meminfo="${MEMCAP_MEMINFO:-/proc/meminfo}"
sudo_cmd="${MEMCAP_SUDO-sudo -n}"
cg="${root}/${MEMCAP_NAME:-ak-ci-memcap-$$}"

# write <value> <file>, as root unless MEMCAP_SUDO is empty.
write() {
  if [[ -n "$sudo_cmd" ]]; then
    printf '%s\n' "$1" | $sudo_cmd tee "$2" >/dev/null 2>&1
  else
    printf '%s\n' "$1" > "$2" 2>/dev/null
  fi
}

gib() { awk -v b="$1" 'BEGIN { printf "%.2f", b / 1073741824 }'; }

uncapped() {
  echo "::warning title=Compile not memory-capped (#6242)::$1; running without a memory.high cap."
  capped=false
}

capped=true
total_kib="$(awk '/^MemTotal:/ { print $2 }' "$meminfo" 2>/dev/null)"
if [[ ! "$total_kib" =~ ^[0-9]+$ ]]; then
  uncapped "cannot read MemTotal from ${meminfo}"
elif (( total_kib / 1024 <= reserve_mib + 1024 )); then
  uncapped "MemTotal $((total_kib / 1024)) MiB leaves under 1 GiB after the ${reserve_mib} MiB reserve"
elif ! grep -qw memory "${root}/cgroup.controllers" 2>/dev/null; then
  uncapped "no cgroup v2 memory controller at ${root}"
else
  high=$(( (total_kib / 1024 - reserve_mib) * 1048576 ))
  # The root must hand the memory controller to its children; systemd
  # normally has, and enabling it again is harmless.
  grep -qw memory "${root}/cgroup.subtree_control" 2>/dev/null || write "+memory" "${root}/cgroup.subtree_control"
  if [[ -n "$sudo_cmd" ]]; then $sudo_cmd mkdir -p "$cg" 2>/dev/null; else mkdir -p "$cg" 2>/dev/null; fi
  if [[ ! -d "$cg" ]]; then
    uncapped "cannot create ${cg}"
  elif ! write "$high" "${cg}/memory.high"; then
    uncapped "cannot set ${cg}/memory.high"
  elif ! write "$$" "${cg}/cgroup.procs"; then
    uncapped "cannot move the compile into ${cg}"
  else
    echo "memory-cap: ${cg}: memory.high $(gib "$high") GiB (MemTotal $(gib $((total_kib * 1024))) GiB minus ${reserve_mib} MiB); swap stays allowed"
  fi
fi

"$@"
status=$?

if [[ "$capped" == true ]]; then
  peak="$(cat "${cg}/memory.peak" 2>/dev/null || echo "")"
  throttled="$(awk '$1 == "high" { print $2 }' "${cg}/memory.events" 2>/dev/null)"
  swap_peak="$(cat "${cg}/memory.swap.peak" 2>/dev/null || echo "")"
  fmt() { if [[ "$1" =~ ^[0-9]+$ ]]; then echo "$(gib "$1") GiB"; else echo "n/a"; fi; }
  echo "memory-cap: ${cg}: memory.peak $(fmt "$peak"), swap peak $(fmt "$swap_peak"), throttled ${throttled:-0} times at memory.high"
  # Leave the cgroup and remove it, so a second capped step starts clean.
  # Best effort: a cgroup that still holds a process is simply left behind.
  write "$$" "${root}/cgroup.procs"
  if [[ -n "$sudo_cmd" ]]; then $sudo_cmd rmdir "$cg" 2>/dev/null; else rmdir "$cg" 2>/dev/null; fi
fi
exit "$status"
