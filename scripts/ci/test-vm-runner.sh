#!/usr/bin/env bash
#
# Self-test for scripts/ci/vm-runner/ak-vm-runner (#6072).
#
# The controller decides when a VM that may hold someone's job is destroyed,
# and what goes into the audit log, so those decisions are pinned here with
# virsh, curl, qemu-img and genisoimage replaced by stubs on PATH:
#
#   - a pool below AKVM_VM_COUNT gets one new VM per pass, registered as a JIT
#     runner with ONLY the configured labels, and the JIT config never stays
#     on disk outside the seed ISO;
#   - a full pool, a drain flag, a full disk or low memory create nothing;
#   - a powered-off VM is destroyed with reason job_finished and its guest
#     job fields land in the audit log, sanitized;
#   - an idle VM past the recycle age is destroyed only when GitHub agrees to
#     remove its registration (422 = busy keeps it);
#   - a VM that never reports runner_start is destroyed after the boot timeout;
#   - the rendered domain XML is well-formed, attaches the egress filter, and
#     attaches the cache disk read-only only when configured.
#
# Usage: bash scripts/ci/test-vm-runner.sh
set -uo pipefail
# The controller's AKVM_* settings are read by the sourced script.
# shellcheck disable=SC2034

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/vm-runner/ak-vm-runner"
[ -f "$SCRIPT" ] || {
  echo "cannot find vm-runner/ak-vm-runner next to this test" >&2
  exit 2
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$*"
  fails=$((fails + 1))
}
check() { # <description> <command...>
  local d="$1"
  shift
  if "$@"; then pass "$d"; else fail "$d"; fi
}

# --- stubs -----------------------------------------------------------------
STUB="$WORK/bin"
mkdir -p "$STUB"
# virsh: domains are files in $FAKE_VIRSH/<name> holding the state.
cat > "$STUB/virsh" << 'EOF'
#!/usr/bin/env bash
while [[ "$1" == -* ]]; do [[ "$1" == -c ]] && shift; shift; done
cmd="$1"; shift
echo "$cmd $*" >> "$FAKE_VIRSH/calls"
case "$cmd" in
  list) [[ -e "$FAKE_VIRSH/LIBVIRT_DOWN" ]] && { echo "error: failed to connect" >&2; exit 1; }
    for f in "$FAKE_VIRSH"/akvm-*; do [[ -f "$f" ]] && basename "$f"; done; exit 0 ;;
  domstate) cat "$FAKE_VIRSH/$1" 2> /dev/null; exit ;;
  dominfo) [[ -f "$FAKE_VIRSH/$1" ]]; exit ;;
  define) n="$(sed -n 's|.*<name>\(.*\)</name>.*|\1|p' "$1" | head -n1)"; echo "shut off" > "$FAKE_VIRSH/$n" ;;
  start) echo running > "$FAKE_VIRSH/$1" ;;
  destroy) [[ -f "$FAKE_VIRSH/$1" ]] && echo "shut off" > "$FAKE_VIRSH/$1" ;;
  undefine) rm -f "$FAKE_VIRSH/$1" ;;
esac
exit 0
EOF
# curl: answers from $FAKE_GH/<METHOD>, records requests.
cat > "$STUB/curl" << 'EOF'
#!/usr/bin/env bash
method=GET body=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -X) method="$2"; shift ;;
    --data-binary) body="$2"; shift ;;
    -K) grep -q 'Authorization: Bearer' "$2" && echo yes > "$FAKE_GH/auth_seen"; shift ;;
    -H|-w|-o) shift ;;
    http*) url="$1" ;;
  esac
  shift
done
printf '%s %s %s\n' "$method" "$url" "$body" >> "$FAKE_GH/requests"
cat "$FAKE_GH/$method"
EOF
cat > "$STUB/qemu-img" << 'EOF'
#!/usr/bin/env bash
[[ "$1" == create ]] && : > "${@: -2:1}"
exit 0
EOF
cat > "$STUB/genisoimage" << 'EOF'
#!/usr/bin/env bash
out=""; files=()
while [[ $# -gt 0 ]]; do
  case "$1" in -output) out="$2"; shift ;; -volid) shift ;; -*) ;; *) files+=("$1") ;; esac
  shift
done
cat "${files[@]}" > "$out"
EOF
chmod +x "$STUB"/*

# Sets up a fresh state dir and sources the controller into this shell.
setup() {
  fails=0 # this case's own count; the parent adds the subshell's exit code
  T="$WORK/case.$RANDOM"
  mkdir -p "$T/virsh" "$T/gh" "$T/state/images/golden"
  export FAKE_VIRSH="$T/virsh" FAKE_GH="$T/gh"
  : > "$FAKE_VIRSH/calls"
  : > "$FAKE_GH/requests"
  printf '{"runner":{"id":4242},"encoded_jit_config":"SEKRETJIT"}\n201' > "$FAKE_GH/POST"
  printf '\n204' > "$FAKE_GH/DELETE"
  : > "$T/state/images/golden/ak-vm-1.qcow2"
  echo abc123 > "$T/state/images/golden/ak-vm-1.qcow2.sha256"
  ln -s ak-vm-1.qcow2 "$T/state/images/golden/current.qcow2"
  echo token > "$T/token"
  export PATH="$STUB:$PATH"
  export AKVM_STATE_DIR="$T/state" AKVM_TOKEN_FILE="$T/token" AKVM_HOST_TAG=t \
    AKVM_VM_COUNT=1 AKVM_LABELS=ak-vm AKVM_CACHE_IMAGE="" RUNTIME_DIRECTORY="$T/run" \
    AKVM_MIN_FREE_PCT=0 AKVM_MIN_HOST_AVAIL_MIB=0 AKVM_VM_MEMORY_MIB=1
  # shellcheck source=scripts/ci/vm-runner/ak-vm-runner
  source "$SCRIPT"
  set +e
}

# Puts a fake running/off VM in place. <name> <state> <age seconds> [console lines...]
fake_vm() {
  local name="$1" state="$2" age="$3"
  shift 3
  mkdir -p "$VMS_DIR/$name" "$CONSOLE_DIR"
  printf 'name=%s\nrunner_id=77\ncreated=%s\nimage=x\n' "$name" "$(($(date +%s) - age))" > "$VMS_DIR/$name/vm.env"
  echo "$state" > "$FAKE_VIRSH/$name"
  printf '%s\r\n' "$@" > "$CONSOLE_DIR/$name.log"
}

audit_has() { grep -q "$1" "$AUDIT_LOG"; }

echo "ak-vm-runner controller"

(
  setup
  reconcile_once
  n="$(find "$FAKE_VIRSH" -name 'akvm-t-*' | wc -l)"
  check "an empty pool gets exactly one new VM per pass" test "$n" -eq 1
  check "the VM is registered with only the configured label" \
    grep -q '"labels":\["ak-vm"\]' "$FAKE_GH/requests"
  check "the JIT request names runner group 1 by default" grep -q '"runner_group_id":1' "$FAKE_GH/requests"
  check "curl can read the token config it is handed" test -s "$FAKE_GH/auth_seen"
  vm="$(basename "$(find "$FAKE_VIRSH" -name 'akvm-t-*')")"
  check "the JIT config lands in the seed ISO" grep -q SEKRETJIT "$VMS_DIR/$vm/seed.iso"
  check "the JIT config is nowhere else in the VM dir or the audit log" \
    bash -c "! grep -rl SEKRETJIT '$VMS_DIR/$vm' '$AUDIT_LOG' | grep -v seed.iso"
  check "vm_created is audited with the runner id and image sha" \
    bash -c "grep -q '\"event\":\"vm_created\"' '$AUDIT_LOG' && grep -q '\"runner_id\":\"4242\"' '$AUDIT_LOG' && grep -q '\"image_sha256\":\"abc123\"' '$AUDIT_LOG'"
  check "the seed ISO is private to its owner" test "$(stat -c %a "$VMS_DIR/$vm/seed.iso")" = 600
  reconcile_once
  n="$(find "$FAKE_VIRSH" -name 'akvm-t-*' | wc -l)"
  check "a full pool creates nothing" test "$n" -eq 1
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  touch "$DRAIN_FLAG"
  reconcile_once
  check "a drained controller creates nothing" test -z "$(find "$FAKE_VIRSH" -name 'akvm-t-*')"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_MIN_FREE_PCT=101
  reconcile_once 2> "$T/err"
  check "a full disk creates nothing" test -z "$(find "$FAKE_VIRSH" -name 'akvm-t-*')"
  check "and says why" grep -q 'disk_free_pct' "$T/err"
  AKVM_MIN_FREE_PCT=0
  AKVM_MIN_HOST_AVAIL_MIB=999999999
  reconcile_once 2> "$T/err"
  check "low host memory creates nothing" test -z "$(find "$FAKE_VIRSH" -name 'akvm-t-*')"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  fake_vm akvm-t-done "shut off" 300 "AKVM event=runner_start kernel=6.8" \
    "AKVM event=job_started repository=artifact-keeper/artifact-keeper run_id=99 job=build sha=deadbeef actor=x\$(rm)" \
    "akvm-t-done login: AKVM event=runner_exit code=0"
  reconcile_once
  check "a powered-off VM is undefined" test ! -e "$FAKE_VIRSH/akvm-t-done"
  check "and its disk directory deleted" test ! -e "$VMS_DIR/akvm-t-done"
  check "and audited as job_finished, even after a login prompt on the same line" audit_has '"reason":"job_finished"'
  check "with the guest-reported run id" audit_has '"guest_run_id":"99"'
  check "and the runner's exit code" audit_has '"guest_code":"0"'
  check "with guest text sanitized" audit_has '"guest_actor":"x__rm_"'
  check "and its runner registration removed (404 tolerated)" grep -q 'DELETE .*/runners/77' "$FAKE_GH/requests"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  fake_vm akvm-t-x "shut off" 300 "AKVM event=runner_start" "AKVM event=runner_exit code=0"
  printf '{"message":"Requires authentication"}\n401' > "$FAKE_GH/DELETE"
  reconcile_once 2> /dev/null
  check "a runner removal that fails is queued" grep -qx 77 "$AKVM_STATE_DIR/runner-deletes-pending"
  printf '\n204' > "$FAKE_GH/DELETE"
  : > "$FAKE_GH/requests"
  reconcile_once 2> /dev/null
  check "and retried on the next pass" grep -q 'DELETE .*/runners/77' "$FAKE_GH/requests"
  check "and dropped from the queue once it succeeds" test ! -s "$AKVM_STATE_DIR/runner-deletes-pending"
  check "and audited" audit_has '"event":"runner_delete_retried"'
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  AKVM_IDLE_RECYCLE_SECONDS=100
  fake_vm akvm-t-busy running 500 "AKVM event=runner_start kernel=6.8"
  printf '{"message":"busy"}\n422' > "$FAKE_GH/DELETE"
  reconcile_once
  check "an idle-aged VM GitHub calls busy is kept" grep -q running "$FAKE_VIRSH/akvm-t-busy"
  check "a busy runner is not queued for later removal" test ! -s "$AKVM_STATE_DIR/runner-deletes-pending"
  printf '\n204' > "$FAKE_GH/DELETE"
  reconcile_once
  check "an idle-aged VM is recycled once its registration is removed" test ! -e "$FAKE_VIRSH/akvm-t-busy"
  check "audited as idle_recycle" audit_has '"reason":"idle_recycle"'
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  AKVM_IDLE_RECYCLE_SECONDS=100
  fake_vm akvm-t-job running 500 "AKVM event=runner_start" "AKVM event=job_started run_id=1"
  reconcile_once
  check "a VM running a job is never idle-recycled" grep -q running "$FAKE_VIRSH/akvm-t-job"
  AKVM_MAX_VM_SECONDS=400
  reconcile_once
  check "but it is destroyed past AKVM_MAX_VM_SECONDS" audit_has '"reason":"max_age"'
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  AKVM_BOOT_TIMEOUT=60
  fake_vm akvm-t-slow running 30
  reconcile_once
  check "a booting VM inside the boot timeout is kept" grep -q running "$FAKE_VIRSH/akvm-t-slow"
  fake_vm akvm-t-stuck running 120
  reconcile_once
  check "a VM with no runner_start past the boot timeout is destroyed" audit_has '"reason":"boot_timeout"'
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  printf '{"message":"Bad credentials"}\n401' > "$FAKE_GH/POST"
  reconcile_once
  check "a failed JIT request defines no VM" test -z "$(find "$FAKE_VIRSH" -name 'akvm-t-*')"
  check "and is audited with the HTTP status" audit_has '"http_status":"401"'
  check "and leaves no VM directory" test -z "$(find "$VMS_DIR" -mindepth 1 -maxdepth 1)"
  : > "$FAKE_GH/requests"
  reconcile_once 2> /dev/null
  check "the next pass backs off instead of asking GitHub again" test ! -s "$FAKE_GH/requests"
  echo 0 > "$AKVM_STATE_DIR/jit-backoff-until"
  printf '{"runner":{"id":1},"encoded_jit_config":"J"}\n201' > "$FAKE_GH/POST"
  reconcile_once 2> /dev/null
  check "after the backoff it retries, and a success clears it" test ! -e "$AKVM_STATE_DIR/jit-failures"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  x="$(render_domain_xml akvm-t-x 1024 2 /d.qcow2 /s.iso /c.log)"
  check "domain XML is well-formed" python3 -I -c 'import sys, xml.dom.minidom as m; m.parseString(sys.stdin.read())' <<< "$x"
  check "domain XML attaches the egress filter" grep -q "<filterref filter='ak-vm-egress'/>" <<< "$x"
  check "domain XML has no cache disk by default" bash -c "! grep -q vdb <<< \"\$1\"" _ "$x"
  check "domain XML destroys the VM on poweroff" grep -q '<on_poweroff>destroy</on_poweroff>' <<< "$x"
  x="$(render_domain_xml akvm-t-x 1024 2 /d.qcow2 /s.iso /c.log /cache.img)"
  check "a configured cache disk is attached read-only and shareable" \
    python3 -I -c '
import sys, xml.dom.minidom as m
d = m.parseString(sys.stdin.read())
disks = [k for k in d.getElementsByTagName("disk") if k.getElementsByTagName("target")[0].getAttribute("dev") == "vdb"]
assert len(disks) == 1 and disks[0].getElementsByTagName("readonly") and disks[0].getElementsByTagName("shareable")
' <<< "$x"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  u="$(render_image_user_data)"
  check "image user-data pins the runner version and checksum" \
    bash -c "base64 -d <<< \"\$(grep -A4 'build-image.sh' <<< \"\$1\" | sed -n 's/^ *content: //p' | head -n1)\" | grep -q \"$AKVM_RUNNER_SHA256\"" _ "$u"
  check "image user-data is cloud-config" test "$(head -n1 <<< "$u")" = "#cloud-config"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  for i in 1 2 3 4 5; do
    : > "$IMAGES_DIR/golden/ak-vm-$i.qcow2"
    touch -d "-$((10 - i)) min" "$IMAGES_DIR/golden/ak-vm-$i.qcow2"
  done
  ln -sfn ak-vm-1.qcow2 "$IMAGES_DIR/golden/current.qcow2"
  AKVM_KEEP_IMAGES=2
  prune_images 2> /dev/null
  check "image pruning succeeds with no VM directories" test $? -eq 0
  check "it keeps the newest images" test -e "$IMAGES_DIR/golden/ak-vm-5.qcow2" -a -e "$IMAGES_DIR/golden/ak-vm-4.qcow2"
  check "it keeps the current image even when old" test -e "$IMAGES_DIR/golden/ak-vm-1.qcow2"
  check "it removes the rest" test ! -e "$IMAGES_DIR/golden/ak-vm-2.qcow2" -a ! -e "$IMAGES_DIR/golden/ak-vm-3.qcow2"
  mkdir -p "$VMS_DIR/akvm-t-old" && echo "image=$IMAGES_DIR/golden/ak-vm-4.qcow2" > "$VMS_DIR/akvm-t-old/vm.env"
  AKVM_KEEP_IMAGES=0
  ln -sfn ak-vm-5.qcow2 "$IMAGES_DIR/golden/current.qcow2"
  prune_images 2> /dev/null
  check "it never removes an image a VM still boots from" test -e "$IMAGES_DIR/golden/ak-vm-4.qcow2"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  fake_vm akvm-t-live running 500 "AKVM event=runner_start"
  mkdir -p "$VMS_DIR/akvm-t-old2" && printf 'created=1\nrunner_id=5\n' > "$VMS_DIR/akvm-t-old2/vm.env"
  touch "$FAKE_VIRSH/LIBVIRT_DOWN"
  reconcile_once 2> /dev/null
  check "a failed libvirt listing is a failed pass" test $? -ne 0
  check "and deletes no VM directory" test -d "$VMS_DIR/akvm-t-live" -a -d "$VMS_DIR/akvm-t-old2"
  check "and creates no VM" test "$(find "$FAKE_VIRSH" -name 'akvm-t-*' | wc -l)" -eq 1
  check "and removes no runner registration" test ! -s "$FAKE_GH/requests"
  rm -f "$FAKE_VIRSH/LIBVIRT_DOWN"
  mkdir -p "$VMS_DIR/akvm-t-new"
  AKVM_VM_COUNT=0
  reconcile_once 2> /dev/null
  check "a directory still being created (no vm.env) is not an orphan" test -d "$VMS_DIR/akvm-t-new"
  mkdir -p "$VMS_DIR/akvm-t-stale" && touch -d "-20 min" "$VMS_DIR/akvm-t-stale"
  reconcile_once 2> /dev/null
  check "but an old one without vm.env (interrupted create) is" test ! -d "$VMS_DIR/akvm-t-stale"
  check "an old directory with no domain is" test ! -d "$VMS_DIR/akvm-t-old2"
  check "and its runner registration is removed" grep -q 'DELETE .*/runners/5' "$FAKE_GH/requests"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  cd "$T" || exit 1
  touch GLOBBED-FILE
  fake_vm akvm-t-g "shut off" 100 "AKVM event=runner_start" \
    "AKVM event=job_started repository=real/repo run_id=1" \
    "AKVM event=job_started repository=forged/repo run_id=666" \
    "AKVM event=runner_exit code=0 x=* *"
  reconcile_once 2> /dev/null
  check "guest text is never glob-expanded" bash -c "! grep -q GLOBBED-FILE '$AUDIT_LOG'"
  check "the first job_started record is the one audited" audit_has '"guest_repository":"real/repo"'
  check "a forged later one is not" bash -c "! grep -q forged '$AUDIT_LOG'"
  check "and the number of job_started records is recorded" audit_has '"guest_job_started_records":"2"'
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  AKVM_BOOT_TIMEOUT=60
  fake_vm akvm-t-rot running 30 "AKVM event=runner_start"
  reconcile_once 2> /dev/null
  check "the seed ISO is ejected once the runner has started" grep -q 'change-media akvm-t-rot sda --eject' "$FAKE_VIRSH/calls"
  rm -f "$CONSOLE_DIR/akvm-t-rot.log"
  sed -i "s/^created=.*/created=$(($(date +%s) - 500))/" "$VMS_DIR/akvm-t-rot/vm.env"
  reconcile_once 2> /dev/null
  check "runner_start seen once survives a rotated, unreadable console" grep -q running "$FAKE_VIRSH/akvm-t-rot"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  AKVM_VM_COUNT=0
  AKVM_CRIT_FREE_PCT=101
  fake_vm akvm-t-idle running 30 "AKVM event=runner_start"
  fake_vm akvm-t-work running 30 "AKVM event=runner_start" "AKVM event=job_started run_id=3"
  fake_vm akvm-t-paused paused 30 "AKVM event=runner_start" "AKVM event=job_started run_id=4"
  reconcile_once 2> /dev/null
  check "below the critical disk floor an idle VM is destroyed" audit_has '"reason":"disk_critical_idle"'
  check "and a paused one" audit_has '"reason":"disk_critical_paused"'
  check "but a VM running a job is not" grep -q running "$FAKE_VIRSH/akvm-t-work"
  exit "$fails"
) || fails=$((fails + $?))

(
  setup
  reconcile_once 2> /dev/null
  check "the GitHub token is never written under the state dir" bash -c "! grep -rq token '$AKVM_STATE_DIR' --exclude=audit.jsonl"
  check "nor under the runtime dir" test ! -e "$T/run"
  x="$(render_domain_xml akvm-t-x 1024 2 /d.qcow2 /s.iso /c.log)"
  check "VM interfaces get an isolated bridge port (no VM-to-VM traffic)" grep -q "<port isolated='yes'/>" <<< "$x"
  exit "$fails"
) || fails=$((fails + $?))

if [ "$fails" -ne 0 ]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
