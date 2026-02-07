#!/bin/bash
# Red Team Test 06: gRPC Unauthenticated Access
# Tests whether gRPC services are accessible without authentication,
# including service enumeration via reflection and direct method invocation.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "gRPC Unauthenticated Access Testing"

# Check if grpcurl is available
if ! command -v grpcurl &>/dev/null; then
    warn "grpcurl not installed; skipping gRPC tests"
    exit 0
fi

info "Target gRPC endpoint: ${GRPC_URL}"

# --- Test 1: Service enumeration via reflection ---
info "Attempting to enumerate gRPC services via reflection (no auth)"

SERVICE_LIST=$(grpcurl -plaintext "$GRPC_URL" list 2>&1) || true

if echo "$SERVICE_LIST" | grep -q "Failed to dial\|connection refused\|context deadline exceeded"; then
    warn "gRPC endpoint not reachable at ${GRPC_URL}"
    info "Response: $(echo "$SERVICE_LIST" | head -c 300)"
    exit 0
fi

if echo "$SERVICE_LIST" | grep -q "Server does not support the reflection API"; then
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

if echo "$DESCRIBE_OUTPUT" | grep -q "Server does not support the reflection API"; then
    pass "Schema describe blocked (reflection disabled)"
elif echo "$DESCRIBE_OUTPUT" | grep -qi "service\|message\|rpc"; then
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

# --- Test 3: Attempt to call SbomService methods without auth ---
info "Attempting to call SbomService.ListSbomsForArtifact without auth"

SBOM_SERVICE="artifact_keeper.sbom.v1.SbomService"

LIST_SBOMS_RESULT=$(grpcurl -plaintext \
    -d '{"repository_name":"test-repo","artifact_name":"test-artifact"}' \
    "$GRPC_URL" "${SBOM_SERVICE}/ListSbomsForArtifact" 2>&1) || true

if echo "$LIST_SBOMS_RESULT" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
    pass "ListSbomsForArtifact correctly requires authentication"
elif echo "$LIST_SBOMS_RESULT" | grep -q "not found\|Unknown service\|Unimplemented"; then
    info "SbomService not available (service not found or unimplemented)"
elif echo "$LIST_SBOMS_RESULT" | grep -q "connection refused\|Failed to dial"; then
    info "gRPC endpoint not reachable for method call"
else
    fail "ListSbomsForArtifact callable without authentication"
    add_finding "CRITICAL" "grpc/sbom-list-noauth" \
        "SbomService.ListSbomsForArtifact is callable without authentication. An attacker can enumerate SBOMs and discover dependency information for all artifacts." \
        "Response: $(echo "$LIST_SBOMS_RESULT" | head -c 1000)"
fi

info "Attempting to call SbomService.GetSbom without auth"

GET_SBOM_RESULT=$(grpcurl -plaintext \
    -d '{"sbom_id":"00000000-0000-0000-0000-000000000000"}' \
    "$GRPC_URL" "${SBOM_SERVICE}/GetSbom" 2>&1) || true

if echo "$GET_SBOM_RESULT" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
    pass "GetSbom correctly requires authentication"
elif echo "$GET_SBOM_RESULT" | grep -q "not found\|Unknown service\|Unimplemented"; then
    info "GetSbom not available (service not found or unimplemented)"
elif echo "$GET_SBOM_RESULT" | grep -q "connection refused\|Failed to dial"; then
    info "gRPC endpoint not reachable for method call"
else
    fail "GetSbom callable without authentication"
    add_finding "CRITICAL" "grpc/sbom-get-noauth" \
        "SbomService.GetSbom is callable without authentication. An attacker can retrieve SBOM documents, which contain detailed dependency and vulnerability information." \
        "Response: $(echo "$GET_SBOM_RESULT" | head -c 1000)"
fi

info "Attempting to call SbomService.GenerateSbom without auth"

GEN_SBOM_RESULT=$(grpcurl -plaintext \
    -d '{"repository_name":"test-repo","artifact_name":"test-artifact","artifact_version":"1.0.0"}' \
    "$GRPC_URL" "${SBOM_SERVICE}/GenerateSbom" 2>&1) || true

if echo "$GEN_SBOM_RESULT" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
    pass "GenerateSbom correctly requires authentication"
elif echo "$GEN_SBOM_RESULT" | grep -q "not found\|Unknown service\|Unimplemented"; then
    info "GenerateSbom not available (service not found or unimplemented)"
elif echo "$GEN_SBOM_RESULT" | grep -q "connection refused\|Failed to dial"; then
    info "gRPC endpoint not reachable for method call"
else
    fail "GenerateSbom callable without authentication"
    add_finding "HIGH" "grpc/sbom-generate-noauth" \
        "SbomService.GenerateSbom is callable without authentication. An attacker could trigger SBOM generation, consuming server resources and potentially triggering scans." \
        "Response: $(echo "$GEN_SBOM_RESULT" | head -c 1000)"
fi

# --- Test 4: Attempt to call sensitive methods (delete, CVE update) ---
info "Attempting to call SbomService.DeleteSbom without auth"

DELETE_RESULT=$(grpcurl -plaintext \
    -d '{"sbom_id":"00000000-0000-0000-0000-000000000000"}' \
    "$GRPC_URL" "${SBOM_SERVICE}/DeleteSbom" 2>&1) || true

if echo "$DELETE_RESULT" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
    pass "DeleteSbom correctly requires authentication"
elif echo "$DELETE_RESULT" | grep -q "not found\|Unknown service\|Unimplemented"; then
    info "DeleteSbom not available (service not found or unimplemented)"
elif echo "$DELETE_RESULT" | grep -q "connection refused\|Failed to dial"; then
    info "gRPC endpoint not reachable for method call"
else
    fail "DeleteSbom callable without authentication"
    add_finding "CRITICAL" "grpc/sbom-delete-noauth" \
        "SbomService.DeleteSbom is callable without authentication. An attacker could delete SBOM records, destroying compliance and vulnerability tracking data." \
        "Response: $(echo "$DELETE_RESULT" | head -c 1000)"
fi

info "Attempting to call SbomService.UpdateCveStatus without auth"

CVE_RESULT=$(grpcurl -plaintext \
    -d '{"sbom_id":"00000000-0000-0000-0000-000000000000","cve_id":"CVE-2024-0001","new_status":"dismissed","comment":"redteam test"}' \
    "$GRPC_URL" "${SBOM_SERVICE}/UpdateCveStatus" 2>&1) || true

if echo "$CVE_RESULT" | grep -q "Unauthenticated\|PermissionDenied\|UNAUTHENTICATED\|PERMISSION_DENIED"; then
    pass "UpdateCveStatus correctly requires authentication"
elif echo "$CVE_RESULT" | grep -q "not found\|Unknown service\|Unimplemented"; then
    info "UpdateCveStatus not available (service not found or unimplemented)"
elif echo "$CVE_RESULT" | grep -q "connection refused\|Failed to dial"; then
    info "gRPC endpoint not reachable for method call"
else
    fail "UpdateCveStatus callable without authentication"
    add_finding "CRITICAL" "grpc/cve-update-noauth" \
        "SbomService.UpdateCveStatus is callable without authentication. An attacker could dismiss CVEs, hiding real vulnerabilities from security teams." \
        "Response: $(echo "$CVE_RESULT" | head -c 1000)"
fi

exit 0
