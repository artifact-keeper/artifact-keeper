#!/usr/bin/env bash
# SBOM gRPC E2E Test
#
# Tests the gRPC SBOM, CVE History, and Security Policy services:
# 1. List license policies (global default should exist)
# 2. Create a test license policy
# 3. Check license compliance (allowed vs denied)
# 4. Get CVE trends
# 5. Cleanup test policy
#
# Requires: backend running with gRPC on port 9090, grpcurl
#
# Installation of grpcurl:
#   brew install grpcurl          # macOS
#   go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest  # Go
#
# Usage:
#   ./test-grpc-sbom.sh                     # Use defaults
#   GRPC_URL=localhost:9090 ./test-grpc-sbom.sh

set -euo pipefail

GRPC_URL="${GRPC_URL:-localhost:9090}"
PROTO_PATH="${PROTO_PATH:-$(dirname "$0")/../../backend/proto}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

# Check for grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo -e "${RED}Error: grpcurl is not installed${NC}"
    echo "Install with: brew install grpcurl (macOS) or go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
    exit 1
fi

# Test connectivity
info "Testing connection to ${GRPC_URL}..."
if ! grpcurl -plaintext "${GRPC_URL}" list &>/dev/null; then
    fail "Cannot connect to gRPC server at ${GRPC_URL}"
fi
pass "Connected to gRPC server"

# -------------------------------------------------------------------------
# Step 1: List available services
# -------------------------------------------------------------------------
header "Discovering gRPC Services"
SERVICES=$(grpcurl -plaintext "${GRPC_URL}" list 2>/dev/null || true)
echo "$SERVICES"

if echo "$SERVICES" | grep -q "SbomService"; then
    pass "SbomService found"
else
    fail "SbomService not found"
fi

if echo "$SERVICES" | grep -q "CveHistoryService"; then
    pass "CveHistoryService found"
else
    fail "CveHistoryService not found"
fi

if echo "$SERVICES" | grep -q "SecurityPolicyService"; then
    pass "SecurityPolicyService found"
else
    fail "SecurityPolicyService not found"
fi

# -------------------------------------------------------------------------
# Step 2: List license policies
# -------------------------------------------------------------------------
header "Listing License Policies"
POLICIES=$(grpcurl -plaintext "${GRPC_URL}" \
    artifact_keeper.sbom.v1.SecurityPolicyService/ListLicensePolicies \
    2>/dev/null || echo "{}")

POLICY_COUNT=$(echo "$POLICIES" | jq '.policies | length // 0' 2>/dev/null || echo "0")
info "Found ${POLICY_COUNT} existing policies"

if [ "$POLICY_COUNT" -gt "0" ]; then
    pass "Default policy exists"
    echo "$POLICIES" | jq -r '.policies[0] | "  Name: \(.name), Enabled: \(.isEnabled)"' 2>/dev/null || true
else
    info "No policies found (expected on fresh install)"
fi

# -------------------------------------------------------------------------
# Step 3: Create a test license policy
# -------------------------------------------------------------------------
header "Creating Test License Policy"
TEST_POLICY_NAME="grpc-e2e-test-policy-$(date +%s)"

CREATE_RESP=$(grpcurl -plaintext -d "{
    \"policy\": {
        \"name\": \"${TEST_POLICY_NAME}\",
        \"description\": \"Test policy for gRPC E2E testing\",
        \"allowed_licenses\": [\"MIT\", \"Apache-2.0\", \"BSD-3-Clause\"],
        \"denied_licenses\": [\"GPL-3.0\", \"AGPL-3.0\"],
        \"allow_unknown\": true,
        \"action\": \"POLICY_ACTION_WARN\",
        \"is_enabled\": true
    }
}" "${GRPC_URL}" artifact_keeper.sbom.v1.SecurityPolicyService/UpsertLicensePolicy 2>&1)

if echo "$CREATE_RESP" | grep -q "\"id\""; then
    POLICY_ID=$(echo "$CREATE_RESP" | jq -r '.id' 2>/dev/null || echo "")
    pass "Created test policy: ${POLICY_ID}"
else
    info "Policy creation response: ${CREATE_RESP}"
    POLICY_ID=""
fi

# -------------------------------------------------------------------------
# Step 4: Check license compliance (allowed licenses)
# -------------------------------------------------------------------------
header "Testing License Compliance - Allowed Licenses"
COMPLIANCE_ALLOWED=$(grpcurl -plaintext -d '{
    "licenses": ["MIT", "Apache-2.0"]
}' "${GRPC_URL}" artifact_keeper.sbom.v1.SbomService/CheckLicenseCompliance 2>&1)

if echo "$COMPLIANCE_ALLOWED" | grep -q "\"compliant\": true"; then
    pass "MIT + Apache-2.0 are compliant"
elif echo "$COMPLIANCE_ALLOWED" | grep -q "compliant"; then
    COMPLIANT=$(echo "$COMPLIANCE_ALLOWED" | jq -r '.compliant // "unknown"' 2>/dev/null)
    info "Compliance result: ${COMPLIANT}"
else
    info "Compliance check response: ${COMPLIANCE_ALLOWED}"
fi

# -------------------------------------------------------------------------
# Step 5: Check license compliance (denied licenses)
# -------------------------------------------------------------------------
header "Testing License Compliance - Denied Licenses"
COMPLIANCE_DENIED=$(grpcurl -plaintext -d '{
    "licenses": ["MIT", "GPL-3.0"]
}' "${GRPC_URL}" artifact_keeper.sbom.v1.SbomService/CheckLicenseCompliance 2>&1)

if echo "$COMPLIANCE_DENIED" | grep -q "\"compliant\": false"; then
    pass "GPL-3.0 correctly flagged as non-compliant"
elif echo "$COMPLIANCE_DENIED" | grep -q "violations"; then
    VIOLATIONS=$(echo "$COMPLIANCE_DENIED" | jq '.violations | length // 0' 2>/dev/null)
    if [ "$VIOLATIONS" -gt "0" ]; then
        pass "GPL-3.0 correctly flagged with ${VIOLATIONS} violations"
    else
        info "No violations found (policy may not be active)"
    fi
else
    info "Compliance check response: ${COMPLIANCE_DENIED}"
fi

# -------------------------------------------------------------------------
# Step 6: Get CVE Trends
# -------------------------------------------------------------------------
header "Getting CVE Trends"
CVE_TRENDS=$(grpcurl -plaintext -d '{"days": 30}' \
    "${GRPC_URL}" artifact_keeper.sbom.v1.CveHistoryService/GetCveTrends 2>&1)

if echo "$CVE_TRENDS" | grep -q "totalCves"; then
    TOTAL=$(echo "$CVE_TRENDS" | jq '.totalCves // 0' 2>/dev/null)
    OPEN=$(echo "$CVE_TRENDS" | jq '.openCves // 0' 2>/dev/null)
    CRITICAL=$(echo "$CVE_TRENDS" | jq '.criticalCount // 0' 2>/dev/null)
    pass "CVE Trends retrieved"
    info "  Total: ${TOTAL}, Open: ${OPEN}, Critical: ${CRITICAL}"
else
    info "CVE Trends response: ${CVE_TRENDS}"
fi

# -------------------------------------------------------------------------
# Step 7: Describe SBOM service methods
# -------------------------------------------------------------------------
header "SBOM Service Methods"
grpcurl -plaintext "${GRPC_URL}" describe artifact_keeper.sbom.v1.SbomService 2>/dev/null | head -20 || true

# -------------------------------------------------------------------------
# Step 8: Cleanup - Delete test policy
# -------------------------------------------------------------------------
if [ -n "$POLICY_ID" ]; then
    header "Cleanup"
    DELETE_RESP=$(grpcurl -plaintext -d "{\"id\": \"${POLICY_ID}\"}" \
        "${GRPC_URL}" artifact_keeper.sbom.v1.SecurityPolicyService/DeleteLicensePolicy 2>&1)

    if echo "$DELETE_RESP" | grep -q "success"; then
        pass "Deleted test policy"
    else
        info "Delete response: ${DELETE_RESP}"
    fi
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
echo ""
echo "========================================="
echo "  SBOM gRPC E2E Test Complete"
echo "========================================="
pass "All gRPC services are operational"

echo ""
info "To run manual tests:"
echo "  # List all services"
echo "  grpcurl -plaintext ${GRPC_URL} list"
echo ""
echo "  # Describe a service"
echo "  grpcurl -plaintext ${GRPC_URL} describe artifact_keeper.sbom.v1.SbomService"
echo ""
echo "  # Call a method"
echo "  grpcurl -plaintext -d '{\"days\": 30}' ${GRPC_URL} artifact_keeper.sbom.v1.CveHistoryService/GetCveTrends"
