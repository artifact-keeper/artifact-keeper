#!/bin/bash
# Red Team Test 06: gRPC Unauthenticated Access
# Tests whether gRPC services are accessible without authentication,
# including service enumeration via reflection and direct method invocation.
#
# #3491: every check below used to score a REFUSAL as a vulnerability. grpcurl
# reports a disabled reflection service as "server does not support the
# reflection API" (lowercase "server"), and the guards here grepped for
# "Server ..." — so the enumeration checks fell through to their else branch
# and reported CRITICAL with the refusal itself pasted in as evidence. The
# method probes had the same shape one layer down: without reflection grpcurl
# cannot resolve a symbol at all, and "could not resolve" matched neither the
# "Unauthenticated" arm nor the "not found" arm, so a call that never left the
# client was reported as "callable without authentication".
#
# Reflection is disabled on purpose, so the method probes are given the .proto
# files instead (PROTO_DIR, mounted by docker-compose.test.yml). When they are
# not available the probes SKIP loudly — an unmeasurable control is reported as
# unmeasured, never as a pass and never as a finding.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "gRPC Unauthenticated Access Testing"

# Check if grpcurl is available
if ! command -v grpcurl &>/dev/null; then
    warn "grpcurl not installed; skipping gRPC tests"
    exit 0
fi

info "Target gRPC endpoint: ${GRPC_URL}"

# grpcurl's wording for "reflection is off" has varied in case and phrasing
# across releases; match it case-insensitively and on the stable substring.
reflection_unavailable() {
    echo "$1" | grep -qi "does not support the reflection api\|unimplemented.*reflection\|unknown service grpc.reflection"
}

endpoint_unreachable() {
    echo "$1" | grep -qi "failed to dial\|connection refused\|context deadline exceeded"
}

# --- Test 1: Service enumeration via reflection ---
info "Attempting to enumerate gRPC services via reflection (no auth)"

SERVICE_LIST=$(grpcurl -plaintext "$GRPC_URL" list 2>&1) || true

if endpoint_unreachable "$SERVICE_LIST"; then
    warn "gRPC endpoint not reachable at ${GRPC_URL}"
    info "Response: $(echo "$SERVICE_LIST" | head -c 300)"
    exit 0
fi

REFLECTION_ENABLED=true
if reflection_unavailable "$SERVICE_LIST"; then
    REFLECTION_ENABLED=false
    pass "Server reflection is disabled (services not enumerable)"
    info "gRPC reflection is properly disabled; attackers cannot discover service definitions"
else
    # Count discovered services (exclude grpc.reflection which is expected if reflection is on)
    APP_SERVICES=$(echo "$SERVICE_LIST" | grep -v "^grpc\.\|^$" | sort) || true
    SERVICE_COUNT=$(echo "$APP_SERVICES" | grep -c "." 2>/dev/null) || true

    if [ "$SERVICE_COUNT" -gt 0 ]; then
        fail "gRPC server reflection is enabled - ${SERVICE_COUNT} application service(s) enumerable without auth"
        add_finding "CRITICAL" "grpc/reflection-enabled" \
            "gRPC server reflection is enabled and exposes ${SERVICE_COUNT} application service(s) without authentication. An attacker can discover the full API surface, including all RPC methods, message types, and field names. This aids in crafting targeted attacks." \
            "Services discovered: ${APP_SERVICES}"

        info "Discovered services:"
        echo "$APP_SERVICES" | while IFS= read -r svc; do
            info "  ${svc}"
        done
    else
        # Reflection works but only grpc internal services visible
        warn "gRPC reflection is enabled but only internal services visible"
        add_finding "LOW" "grpc/reflection-internal-only" \
            "gRPC server reflection is enabled but only exposes internal gRPC services. Consider disabling reflection in production to reduce the attack surface." \
            "Services: $(echo "$SERVICE_LIST" | tr '\n' ' ')"
    fi
fi

# --- Test 2: Full schema discovery via describe ---
info "Attempting full schema describe (no auth)"

DESCRIBE_OUTPUT=$(grpcurl -plaintext "$GRPC_URL" describe 2>&1) || true

if reflection_unavailable "$DESCRIBE_OUTPUT"; then
    pass "Schema describe blocked (reflection disabled)"
elif echo "$DESCRIBE_OUTPUT" | grep -qE "^[[:space:]]*(service|message) |[[:space:]]rpc "; then
    # Count message types and rpc methods exposed
    RPC_COUNT=$(echo "$DESCRIBE_OUTPUT" | grep -c "rpc " 2>/dev/null) || true
    MSG_COUNT=$(echo "$DESCRIBE_OUTPUT" | grep -c "message " 2>/dev/null) || true

    fail "Full gRPC schema exposed: ${RPC_COUNT} RPCs, ${MSG_COUNT} message types"
    add_finding "CRITICAL" "grpc/schema-exposed" \
        "Full gRPC schema is accessible without authentication. Discovered ${RPC_COUNT} RPC methods and ${MSG_COUNT} message types. This reveals the entire API contract including sensitive operations." \
        "Schema describe output (truncated): $(echo "$DESCRIBE_OUTPUT" | head -c 2000)"
else
    pass "Schema describe did not reveal service definitions"
fi

# --- Tests 3 & 4: call SbomService methods without auth ---
#
# With reflection off grpcurl needs the .proto files to build a request, so
# without them these probes cannot be performed at all.
SBOM_SERVICE="artifact_keeper.sbom.v1.SbomService"
SBOM_PROTO="${PROTO_DIR}/sbom.proto"
GRPC_SCHEMA_ARGS=()

if [ "$REFLECTION_ENABLED" = false ]; then
    if [ -r "$SBOM_PROTO" ]; then
        GRPC_SCHEMA_ARGS=(-import-path "$PROTO_DIR" -proto "sbom.proto")
        info "Reflection is disabled; invoking methods from ${SBOM_PROTO}"
    else
        info "Reflection is disabled and no .proto files are available at ${PROTO_DIR}"
        info "SKIPPING the unauthenticated method probes — they cannot be performed, which is not the same as passing"
        exit 0
    fi
fi

# probe_method <rpc name> <json request> <severity> <finding id> <description>
probe_method() {
    local method="$1" payload="$2" severity="$3" finding="$4" description="$5"
    local result

    info "Attempting to call SbomService.${method} without auth"

    result=$(grpcurl -plaintext ${GRPC_SCHEMA_ARGS[@]+"${GRPC_SCHEMA_ARGS[@]}"} \
        -d "$payload" "$GRPC_URL" "${SBOM_SERVICE}/${method}" 2>&1) || true

    if echo "$result" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
        pass "${method} correctly requires authentication"
    elif echo "$result" | grep -qi "unknown service\|unimplemented\|not found"; then
        info "${method} not available (service not found or unimplemented)"
    elif endpoint_unreachable "$result"; then
        info "gRPC endpoint not reachable for method call"
    elif reflection_unavailable "$result" || echo "$result" | grep -qi "could not resolve\|failed to resolve\|no such file\|could not parse"; then
        # The call never reached the server: grpcurl could not build it. That
        # is a harness limitation, not a server finding (#3491).
        warn "${method} could not be probed (grpcurl could not resolve the schema)"
        info "grpcurl: $(echo "$result" | head -c 300)"
    else
        fail "${method} callable without authentication"
        add_finding "$severity" "$finding" "$description" \
            "Response: $(echo "$result" | head -c 1000)"
    fi
}

probe_method "ListSbomsForArtifact" \
    '{"repository_name":"test-repo","artifact_name":"test-artifact"}' \
    "CRITICAL" "grpc/sbom-list-noauth" \
    "SbomService.ListSbomsForArtifact is callable without authentication. An attacker can enumerate SBOMs and discover dependency information for all artifacts."

probe_method "GetSbom" \
    '{"sbom_id":"00000000-0000-0000-0000-000000000000"}' \
    "CRITICAL" "grpc/sbom-get-noauth" \
    "SbomService.GetSbom is callable without authentication. An attacker can retrieve SBOM documents, which contain detailed dependency and vulnerability information."

probe_method "GenerateSbom" \
    '{"repository_name":"test-repo","artifact_name":"test-artifact","artifact_version":"1.0.0"}' \
    "HIGH" "grpc/sbom-generate-noauth" \
    "SbomService.GenerateSbom is callable without authentication. An attacker could trigger SBOM generation, consuming server resources and potentially triggering scans."

probe_method "DeleteSbom" \
    '{"sbom_id":"00000000-0000-0000-0000-000000000000"}' \
    "CRITICAL" "grpc/sbom-delete-noauth" \
    "SbomService.DeleteSbom is callable without authentication. An attacker could delete SBOM records, destroying compliance and vulnerability tracking data."

probe_method "UpdateCveStatus" \
    '{"sbom_id":"00000000-0000-0000-0000-000000000000","cve_id":"CVE-2024-0001","new_status":"dismissed","comment":"redteam test"}' \
    "CRITICAL" "grpc/cve-update-noauth" \
    "SbomService.UpdateCveStatus is callable without authentication. An attacker could dismiss CVEs, hiding real vulnerabilities from security teams."

exit 0
