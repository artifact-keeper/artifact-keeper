#!/bin/sh
# Guest-to-guest isolation check for the sandbox network topology (#5447).
# docs/security/mcp-sandbox.md, "Check before enabling".
#
# Builds, with throwaway names, the topology the worker builds for every npm
# or PyPI guest: an internal network per guest that only the forwarder also
# joins (under an AK-like alias), and, as the worker does, the forwarder's
# address on that network read back with `container inspect` and given to
# the guest as `--add-host <alias>:<address>` (the guest does not depend on
# the engine's DNS, which a gVisor guest on an internal Docker network
# cannot reach). Then, from an attacker guest, it checks:
#
#   1. the forwarder answers on the alias        (must connect)
#   2. a second guest on its own network          (must NOT connect)
#   3. the forwarder's address on that network   (must NOT connect)
#   4. a default route                            (must NOT exist)
#   5. the internet, $EGRESS_HOST:$EGRESS_PORT   (must NOT connect)
#   6. an outside name (example.com) in DNS       (must NOT resolve)
#
# and controls, so a probe that silently cannot connect at all cannot pass:
# a guest that shares the victim's network DOES reach it (the non-isolated
# control), a guest on the forwarder's ordinary egress network DOES reach
# the internet (when the host has internet; otherwise check 5 is reported
# inconclusive and check 4 decides), and an OCI-style `--network=none`
# guest does not reach the victim. The victim records every connection it
# accepts; the check fails unless exactly the control's connection was
# recorded. The test forwarder runs with IP forwarding off, as the
# reference compose file sets it; the check fails if it is on there, or in
# the deployed forwarder (`$GATEWAY`, default `ak-gateway`) when that
# container exists.
#
# Run it as the worker's user, with the worker's engine and runtime:
#
#   ENGINE=podman RUNTIME=runsc sh guest-isolation-check.sh
#
# RUNTIME= (empty) uses the engine's default runtime, for a topology-only
# check. IMAGE must contain busybox `nc`, `ip` and `nslookup` (alpine does).
# SHARED=1 is the policy-removed control: the attacker joins the victim's
# network, as every guest did on the old shared `ak-mcp-sandbox` bridge, and
# the check must then FAIL.
set -u

ENGINE=${ENGINE:-podman}
RUNTIME=${RUNTIME-runsc}
IMAGE=${IMAGE:-docker.io/library/alpine:3.20}
GATEWAY=${GATEWAY:-ak-gateway}
EGRESS_HOST=${EGRESS_HOST:-1.1.1.1}
EGRESS_PORT=${EGRESS_PORT:-80}
ALIAS=ak.sandbox-check.test
P="ak-sbx-check-$$"
FAIL=0
ATTACKER_NET="$P-a"
[ "${SHARED:-0}" = 1 ] && ATTACKER_NET="$P-b"

rt() { [ -n "$RUNTIME" ] && printf -- '--runtime=%s' "$RUNTIME"; }
guest() { # guest <network> <shell script>
    net=$1; shift
    hosts=
    [ "$net" = "$ATTACKER_NET" ] && hosts="--add-host=$ALIAS:$GW_ATTACKER"
    # shellcheck disable=SC2046,SC2086
    "$ENGINE" run --rm $(rt) --network="$net" $hosts --read-only --cap-drop=ALL \
        --security-opt=no-new-privileges --user=65532:65532 "$IMAGE" sh -c "$1"
}
ip_on() { # ip_on <container> <network>: the worker's own lookup
    "$ENGINE" container inspect --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"
}
fail() { echo "FAIL $1"; FAIL=1; }
forwarding() { # forwarding <container>: its ip_forward and IPv6 forwarding
    "$ENGINE" exec "$1" cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null | tr -d '\n'
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
trap cleanup EXIT
trap 'exit 130' INT TERM

set -e
"$ENGINE" pull -q "$IMAGE" >/dev/null
"$ENGINE" network create "$P-egress" >/dev/null
"$ENGINE" network create --internal "$P-a" >/dev/null
"$ENGINE" network create --internal "$P-b" >/dev/null
# The sysctls compose.sandbox-network.yaml sets on the real forwarder.
"$ENGINE" run -d --name "$P-gw" --network="$P-egress" \
    --sysctl net.ipv4.ip_forward=0 --sysctl net.ipv6.conf.all.forwarding=0 \
    "$IMAGE" nc -lk -p 443 -e echo forwarder >/dev/null
"$ENGINE" network connect --alias "$ALIAS" "$P-a" "$P-gw"
"$ENGINE" network connect --alias "$ALIAS" "$P-b" "$P-gw"
# shellcheck disable=SC2046
"$ENGINE" run -d --name "$P-victim" $(rt) --network="$P-b" "$IMAGE" \
    nc -lk -p 8080 -e sh -c 'echo connection >&2; echo victim' >/dev/null
VICTIM=$(ip_on "$P-victim" "$P-b")
GW_B=$(ip_on "$P-gw" "$P-b")
GW_ATTACKER=$(ip_on "$P-gw" "$ATTACKER_NET")
set +e
sleep 1
for a in "$VICTIM" "$GW_B" "$GW_ATTACKER"; do
    case "$a" in
        *[!0-9a-f.:]* | "")
            fail "could not read the guest addresses (victim '$VICTIM', forwarder '$GW_B' / '$GW_ATTACKER')"
            exit 1 ;;
    esac
done

out=$(guest "$ATTACKER_NET" "nc -w 3 $ALIAS 443 </dev/null")
rc=1; [ "$out" = forwarder ] && rc=0
check "attacker -> forwarder ($ALIAS:443)" 0 "$rc"
guest "$ATTACKER_NET" "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "attacker -> second guest ($VICTIM:8080)" 1 $?
guest "$ATTACKER_NET" "nc -w 3 $GW_B 443 </dev/null | grep -q forwarder"
check "attacker -> forwarder on the other guest's network ($GW_B:443)" 1 $?
guest "$ATTACKER_NET" "ip route | grep -q '^default'"
check "attacker has a default route" 1 $?
guest "$P-egress" "nc -w 3 $EGRESS_HOST $EGRESS_PORT </dev/null"
control=$?
guest "$ATTACKER_NET" "nc -w 3 $EGRESS_HOST $EGRESS_PORT </dev/null"
attacker=$?
if [ "$control" -eq 0 ]; then
    check "attacker -> internet ($EGRESS_HOST:$EGRESS_PORT; the egress control connected)" 1 "$attacker"
elif [ "$attacker" -eq 0 ]; then
    fail "attacker -> internet ($EGRESS_HOST:$EGRESS_PORT): connected"
else
    echo "--   attacker -> internet: inconclusive (the egress control could not connect either)"
fi
guest "$ATTACKER_NET" "nslookup example.com >/dev/null 2>&1"
check "attacker resolves an outside name (example.com)" 1 $?
guest none "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "network=none guest -> second guest" 1 $?
guest "$P-b" "nc -w 3 $VICTIM 8080 </dev/null | grep -q victim"
check "control: guest sharing the victim's network -> victim" 0 $?

for c in "$P-gw" "$GATEWAY"; do
    if [ "$c" = "$GATEWAY" ] && ! "$ENGINE" container inspect "$GATEWAY" >/dev/null 2>&1; then
        echo "--   deployed forwarder $GATEWAY: not running here, not checked"
        continue
    fi
    fw=$(forwarding "$c")
    case "$fw" in
        00) echo "ok   forwarder $c: IP forwarding off" ;;
        *) fail "forwarder $c: IP forwarding not off (ipv4/ipv6: '$fw'); set the sysctls in compose.sandbox-network.yaml" ;;
    esac
done

sleep 1
seen=$("$ENGINE" logs "$P-victim" 2>&1 | grep -c '^connection$')
if [ "$seen" -eq 1 ]; then
    echo "ok   victim recorded exactly the control's connection"
else
    echo "FAIL victim recorded $seen connection(s), expected 1 (the control's)"; FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "guest isolation: PASS" || echo "guest isolation: FAIL"
exit "$FAIL"
