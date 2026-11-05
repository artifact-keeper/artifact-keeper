#!/bin/sh
# ak-mcp-introspector external runner for Kubernetes (#5253).
# Started as `k8s-launcher.sh '<guest spec JSON>'`; its stdin/stdout become
# the guest's. One pod per job in the ak-mcp-sandbox namespace, gVisor
# runtime class, the restricted security context the OCI runner applies,
# deleted when the probe ends (the worker kills this process at the wall
# clock; activeDeadlineSeconds is the cluster-side backstop).
# Needs kubectl and jq.
set -eu
spec=$1
ns=${AK_MCP_SANDBOX_NAMESPACE:-ak-mcp-sandbox}
runtime_class=${AK_MCP_SANDBOX_RUNTIME_CLASS:-gvisor}
job=$(printf '%s' "$spec" | jq -r '.jobId' | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' \
  | cut -c1-40 | sed 's/^-*//; s/-*$//')
image=$(printf '%s' "$spec" | jq -r '.image')
overrides=$(printf '%s' "$spec" | jq -c --arg rc "$runtime_class" '{
  apiVersion: "v1",
  metadata: {labels: {
    "app.kubernetes.io/name": "ak-mcp-sandbox-guest",
    "ak-mcp-sandbox/network": (if .network == "none" then "none" else "ak-only" end)}},
  spec: {
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
  }}')
exec kubectl run "ak-mcp-sbx-$job" --namespace "$ns" --image "$image" \
  --restart=Never --rm --quiet -i --attach \
  --pod-running-timeout=90s --overrides "$overrides"
