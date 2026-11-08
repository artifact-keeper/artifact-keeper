#!/bin/sh
# Guest-to-guest isolation check for the sandbox network topology (#5447).
# docs/security/mcp-sandbox.md, "Check before enabling".
#
# Builds, with throwaway names, the topology the worker builds for every npm
# or PyPI guest: an internal network per guest that only the forwarder also
# joins (under an AK-like alias). Then, from an attacker guest, it checks:
#
#   1. the forwarder answers on the alias        (must connect)
#   2. a second guest on its own network          (must NOT connect)
#   3. the forwarder's address on that network   (must NOT connect)
#   4. the internet                               (must NOT connect)
#
# and two controls, so a probe that silently cannot connect at all cannot
# pass: a guest that shares the victim's network DOES reach it (the
# non-isolated control), and an OCI-style `--network=none` guest does not.
# The victim records every connection it accepts; the check fails unless
# exactly the control's connection was recorded.
#
# Run it as the worker's user, with the worker's engine and runtime:
#
#   ENGINE=podman RUNTIME=runsc sh guest-isolation-check.sh
#
# RUNTIME= (empty) uses the engine's default runtime, for a topology-only
# check. IMAGE must contain busybox `nc` and `wget` (alpine does).
# SHARED=1 is the policy-removed control: the attacker joins the victim's
# network, as every guest did on the old shared `ak-mcp-sandbox` bridge, and
# the check must then FAIL.
set -u

ENGINE=${ENGINE:-podman}
RUNTIME=${RUNTIME-runsc}
IMAGE=${IMAGE:-docker.io/library/alpine:3.20}
ALIAS=ak.sandbox-check.test
P="ak-sbx-check-$$"
FAIL=0
ATTACKER_NET="$P-a"
[ "${SHARED:-0}" = 1 ] && ATTACKER_NET="$P-b"

rt() { [ -n "$RUNTIME" ] && printf -- '--runtime=%s' "$RUNTIME"; }
guest() { # guest <network> <shell script>
    net=$1; shift
    # shellcheck disable=SC2046
    "$ENGINE" run --rm $(rt) --network="$net" --read-only --cap-drop=ALL \
        --security-opt=no-new-privileges --user=65532:65532 "$IMAGE" sh -c "$1"
}
ip_on() { # ip_on <container> <network>
    "$ENGINE" inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
check() { # check <description> <expected 0|1> <actual exit>
    if [ "$3" -eq 0 ]; then got=connected; else got=refused; fi
    if { [ "$2" -eq 0 ] && [ "$3" -eq 0 ]; } || { [ "$2" -ne 0 ] && [ "$3" -ne 0 ]; }; then
        echo "ok   $1: $got"
    else
        echo "FAIL $1: $got"; FAIL=1
    fi
}
# shellcheck disable=SC2329 # run by the trap
cleanup() {
    "$ENGINE" rm -f "$P-gw" "$P-victim" >/dev/null 2>&1
    for n in "$P-a" "$P-b" "$P-egress"; do
        "$ENGINE" network rm "$n" >/dev/null 2>&1
    done
}
trap cleanup EXIT INT TERM

set -e
"$ENGINE" pull -q "$IMAGE" >/dev/null
"$ENGINE" network create "$P-egress" >/dev/null
"$ENGINE" network create --internal "$P-a" >/dev/null
"$ENGINE" network create --internal "$P-b" >/dev/null
"$ENGINE" run -d --name "$P-gw" --network="$P-egress" "$IMAGE" \
    nc -lk -p 443 -e echo forwarder >/dev/null
"$ENGINE" network connect --alias "$ALIAS" "$P-a" "$P-gw"
"$ENGINE" network connect --alias "$ALIAS" "$P-b" "$P-gw"
# shellcheck disable=SC2046
"$ENGINE" run -d --name "$P-victim" $(rt) --network="$P-b" "$IMAGE" \
    nc -lk -p 8080 -e sh -c 'echo connection >&2; echo victim' >/dev/null
VICTIM=$(ip_on "$P-victim" "$P-b")
GW_B=$(ip_on "$P-gw" "$P-b")
set +e
sleep 1

out=$(guest "$ATTACKER_NET" "nc -w 3 $ALIAS 443 </dev/null")
rc=1; [ "$out" = forwarder ] && rc=0
check "attacker -> forwarder ($ALIAS:443)" 0 "$rc"
guest "$ATTACKER_NET" "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "attacker -> second guest ($VICTIM:8080)" 1 $?
guest "$ATTACKER_NET" "nc -w 3 $GW_B 443 </dev/null | grep -q forwarder"
check "attacker -> forwarder on the other guest's network ($GW_B:443)" 1 $?
guest "$ATTACKER_NET" "wget -q -T 3 -O /dev/null http://1.1.1.1/ 2>/dev/null"
check "attacker -> internet (1.1.1.1:80)" 1 $?
guest none "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "network=none guest -> second guest" 1 $?
guest "$P-b" "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "control: guest sharing the victim's network -> victim" 0 $?

sleep 1
seen=$("$ENGINE" logs "$P-victim" 2>&1 | grep -c '^connection$')
if [ "$seen" -eq 1 ]; then
    echo "ok   victim recorded exactly the control's connection"
else
    echo "FAIL victim recorded $seen connection(s), expected 1 (the control's)"; FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "guest isolation: PASS" || echo "guest isolation: FAIL"
exit "$FAIL"
