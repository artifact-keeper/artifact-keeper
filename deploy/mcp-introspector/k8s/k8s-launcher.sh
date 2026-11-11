#!/bin/sh
# ak-mcp-introspector external runner for Kubernetes (#5253).
# Started as `k8s-launcher.sh '<guest spec JSON>'`; its stdin/stdout become
# the guest's. One pod per attempt (a fresh name each time) in the
# ak-mcp-sandbox namespace, gVisor runtime class, the restricted security
# context the OCI runner applies. The pod is deleted when the probe ends:
# the worker sends this script SIGTERM at the wall clock (SIGKILL 5 s
# later), and the trap deletes the pod; pods a killed launcher left behind
# for the same job are deleted before the next attempt starts, and
# activeDeadlineSeconds is the cluster-side backstop.
#
# With AK_MCP_SANDBOX_AK_IP (and AK_MCP_SANDBOX_AK_HOST, the AK hostname)
# set, the guest resolves the AK host through hostAliases and gets no DNS
# server at all (dnsPolicy None, nameserver 127.0.0.1), so DNS is not a
# way out (networkpolicy.yaml).
# Needs kubectl, jq and od.
set -eu
spec=$1
ns=${AK_MCP_SANDBOX_NAMESPACE:-ak-mcp-sandbox}
runtime_class=${AK_MCP_SANDBOX_RUNTIME_CLASS:-gvisor}
ak_ip=${AK_MCP_SANDBOX_AK_IP:-}
ak_host=${AK_MCP_SANDBOX_AK_HOST:-}
job=$(printf '%s' "$spec" | jq -r '.jobId' | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' \
  | cut -c1-40 | sed 's/^-*//; s/-*$//')
pod="ak-mcp-sbx-$job-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
image=$(printf '%s' "$spec" | jq -r '.image')
overrides=$(printf '%s' "$spec" | jq -c --arg rc "$runtime_class" --arg job "$job" \
  --arg ak_ip "$ak_ip" --arg ak_host "$ak_host" '{
  apiVersion: "v1",
  metadata: {labels: {
    "app.kubernetes.io/name": "ak-mcp-sandbox-guest",
    "ak-mcp-sandbox/job": $job,
    "ak-mcp-sandbox/network": (if .network == "none" then "none" else "ak-only" end)}},
  spec: ({
    runtimeClassName: $rc,
    automountServiceAccountToken: false,
    enableServiceLinks: false,
    restartPolicy: "Never",
    activeDeadlineSeconds: ((.wallClockMs / 1000 | floor) + 10),
    securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532,
                      seccompProfile: {type: "RuntimeDefault"}},
    volumes: [{name: "tmp", emptyDir: {medium: "Memory", sizeLimit: "512Mi"}}],
    containers: [({
      name: "guest", image: .image, stdin: true, stdinOnce: true, tty: false,
      workingDir: "/tmp",
      env: [.env[] | {name: .[0], value: .[1]}],
      volumeMounts: [{name: "tmp", mountPath: "/tmp"}],
      resources: {limits: {memory: "1Gi", cpu: "1"}, requests: {memory: "256Mi", cpu: "100m"}},
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true,
                        capabilities: {drop: ["ALL"]}}
    } + (if (.argv | length) > 0 then {args: .argv} else {} end))]
  } + (if $ak_ip != "" then {
    hostAliases: [{ip: $ak_ip, hostnames: [$ak_host]}],
    dnsPolicy: "None",
    dnsConfig: {nameservers: ["127.0.0.1"]}
  } else {} end))}')

delete_pod() {
  kubectl delete pod "$pod" --namespace "$ns" --ignore-not-found --wait=false \
    --grace-period=0 --force >/dev/null 2>&1 || true
}
on_signal() {
  [ -n "${kpid:-}" ] && kill "$kpid" 2>/dev/null
  delete_pod
  exit 143
}
trap on_signal TERM INT HUP

# Pods of earlier attempts of this job whose launcher was killed.
kubectl delete pod --namespace "$ns" -l "ak-mcp-sandbox/job=$job" --ignore-not-found \
  --wait=false --grace-period=0 --force >/dev/null 2>&1 || true

# kubectl runs in the background so the trap can fire; fd 3 carries the
# guest's stdin (a background job's own stdin would be /dev/null).
exec 3<&0
kubectl run "$pod" --namespace "$ns" --image "$image" \
  --restart=Never --rm --quiet -i --attach \
  --pod-running-timeout=90s --overrides "$overrides" <&3 &
kpid=$!
rc=0
wait "$kpid" || rc=$?
delete_pod
exit "$rc"
