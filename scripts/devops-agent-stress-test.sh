#!/usr/bin/env bash
#
# DevOps Agent Stress Test
# Comprehensive stress testing for Artifact Keeper backend
#
# Tests: Repository CRUD, artifact uploads across formats, staging/promotion,
#        security scanning, edge cases, concurrent operations, and more.
#
# Usage:
#   ./scripts/devops-agent-stress-test.sh
#   REGISTRY_URL=http://localhost:30080 ./scripts/devops-agent-stress-test.sh
#
set -o pipefail

# Rate limit mitigation: add small delay between API calls
RATE_DELAY="${RATE_DELAY:-0.15}"
rate_wait() { sleep "$RATE_DELAY"; }

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/devops-stress-results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0
BUGS=()

mkdir -p "$RESULTS_DIR"

log_pass() { ((PASS++)); echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { ((FAIL++)); echo -e "${RED}[FAIL]${NC} $1"; BUGS+=("$1"); }
log_warn() { ((WARN++)); echo -e "${YELLOW}[WARN]${NC} $1"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_section() { echo ""; echo -e "${CYAN}═══════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════${NC}"; }

# Get auth token
get_token() {
    curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null
}

# Authenticated request helper
api() {
    local method="$1"
    local path="$2"
    shift 2
    sleep "$RATE_DELAY"
    curl -sf -X "$method" "$REGISTRY_URL$path" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "$@" 2>/dev/null
}

# Authenticated request - return status code
api_status() {
    local method="$1"
    local path="$2"
    shift 2
    sleep "$RATE_DELAY"
    curl -s -o /dev/null -w "%{http_code}" -X "$method" "$REGISTRY_URL$path" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "$@" 2>/dev/null
}

# Authenticated request - return full response with status (with retry on 429)
api_full() {
    local method="$1"
    local path="$2"
    shift 2
    local tmpfile=$(mktemp)
    local status
    local retries=3
    while [ "$retries" -gt 0 ]; do
        sleep "$RATE_DELAY"
        status=$(curl -s -w "%{http_code}" -o "$tmpfile" -X "$method" "$REGISTRY_URL$path" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$@" 2>/dev/null)
        if [ "$status" = "429" ] && [ "$retries" -gt 1 ]; then
            ((retries--))
            sleep 2  # back off on rate limit
            continue
        fi
        break
    done
    echo "$status|$(cat "$tmpfile")"
    rm -f "$tmpfile"
}

cleanup_repo() {
    local key="$1"
    api DELETE "/api/v1/repositories/$key" >/dev/null 2>&1 || true
}

# ============================================================
echo -e "${CYAN}"
echo "  ____             ___                _                    _   "
echo " |  _ \\  _____   _/ _ \\ _ __  ___    / \\   __ _  ___ _ __ | |_ "
echo " | | | |/ _ \\ \\ / / | | | '_ \\/ __|  / _ \\ / _\` |/ _ \\ '_ \\| __|"
echo " | |_| |  __/\\ V /| |_| | |_) \\__ \\ / ___ \\ (_| |  __/ | | | |_ "
echo " |____/ \\___| \\_/  \\___/| .__/|___//_/   \\_\\__, |\\___|_| |_|\\__|"
echo "                        |_|                |___/               "
echo -e "${NC}"
echo "Registry: $REGISTRY_URL"
echo "Results:  $RESULTS_DIR"
echo "Time:     $(date)"
echo ""

# ============================================================
log_section "Phase 0: Pre-flight Checks"
# ============================================================

log_info "Checking backend health..."
HEALTH=$(curl -sf "$REGISTRY_URL/health" 2>/dev/null || echo '{"status":"unreachable"}')
STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
if [ "$STATUS" = "healthy" ]; then
    log_pass "Backend is healthy"
else
    log_fail "Backend health check failed: $STATUS"
    echo "$HEALTH"
    exit 1
fi

log_info "Authenticating..."
TOKEN=$(get_token)
if [ -n "$TOKEN" ]; then
    log_pass "Authentication successful"
else
    log_fail "Authentication failed"
    exit 1
fi

# ============================================================
log_section "Phase 1: Repository CRUD Operations"
# ============================================================

# --- Test: Create repositories for each format ---
FORMATS=("generic" "maven" "npm" "pypi" "docker" "helm" "cargo" "nuget" "debian" "rpm" "rubygems" "go")
CREATED_REPOS=()

for fmt in "${FORMATS[@]}"; do
    KEY="stress-${fmt}-local-${TIMESTAMP}"
    RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$KEY\",\"name\":\"Stress $fmt Local\",\"format\":\"$fmt\",\"repo_type\":\"local\",\"is_public\":true}")
    CODE="${RESP%%|*}"
    BODY="${RESP#*|}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
        log_pass "Create $fmt local repo ($KEY)"
        CREATED_REPOS+=("$KEY")
    else
        log_fail "Create $fmt local repo: HTTP $CODE - $(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('message',''))" 2>/dev/null || echo "$BODY")"
    fi
done

# --- Test: Create staging repos ---
STAGING_FORMATS=("generic" "maven" "npm" "pypi")
STAGING_REPOS=()
for fmt in "${STAGING_FORMATS[@]}"; do
    KEY="stress-${fmt}-staging-${TIMESTAMP}"
    RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$KEY\",\"name\":\"Stress $fmt Staging\",\"format\":\"$fmt\",\"repo_type\":\"staging\"}")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
        log_pass "Create $fmt staging repo ($KEY)"
        STAGING_REPOS+=("$KEY")
    else
        log_fail "Create $fmt staging repo: HTTP $CODE"
    fi
done

# --- Test: Create virtual repos with members ---
for fmt in "maven" "npm"; do
    VKEY="stress-${fmt}-virtual-${TIMESTAMP}"
    LKEY="stress-${fmt}-local-${TIMESTAMP}"
    RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$VKEY\",\"name\":\"Stress $fmt Virtual\",\"format\":\"$fmt\",\"repo_type\":\"virtual\"}")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
        log_pass "Create $fmt virtual repo"
        # Add member
        MRESP=$(api_full POST "/api/v1/repositories/$VKEY/members" -d "{\"member_key\":\"$LKEY\",\"priority\":1}")
        MCODE="${MRESP%%|*}"
        if [ "$MCODE" = "200" ] || [ "$MCODE" = "201" ]; then
            log_pass "Add $LKEY as member of $VKEY"
        else
            log_fail "Add virtual member: HTTP $MCODE - ${MRESP#*|}"
        fi
        CREATED_REPOS+=("$VKEY")
    else
        log_fail "Create $fmt virtual repo: HTTP $CODE"
    fi
done

# --- Test: Create remote repos ---
RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"stress-pypi-remote-${TIMESTAMP}\",\"name\":\"Stress PyPI Remote\",\"format\":\"pypi\",\"repo_type\":\"remote\",\"upstream_url\":\"https://pypi.org\"}")
CODE="${RESP%%|*}"
if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    log_pass "Create pypi remote repo with upstream URL"
    CREATED_REPOS+=("stress-pypi-remote-${TIMESTAMP}")
else
    log_fail "Create pypi remote repo: HTTP $CODE"
fi

# --- Test: Duplicate key should fail ---
DUP_KEY="stress-generic-local-${TIMESTAMP}"
RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$DUP_KEY\",\"name\":\"Duplicate\",\"format\":\"generic\",\"repo_type\":\"local\"}")
CODE="${RESP%%|*}"
if [ "$CODE" = "409" ] || [ "$CODE" = "400" ]; then
    log_pass "Duplicate repo key properly rejected (HTTP $CODE)"
elif [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    log_fail "Duplicate repo key was accepted (should be 409/400)"
else
    log_warn "Duplicate repo key returned unexpected HTTP $CODE"
fi

# --- Test: Update repo ---
UPD_KEY="stress-generic-local-${TIMESTAMP}"
RESP=$(api_full PATCH "/api/v1/repositories/$UPD_KEY" -d '{"name":"Updated Name","description":"stress test updated"}')
CODE="${RESP%%|*}"
if [ "$CODE" = "200" ]; then
    log_pass "Update repository name and description"
else
    log_fail "Update repository: HTTP $CODE"
fi

# --- Test: List repos with pagination ---
RESP=$(api GET "/api/v1/repositories?per_page=5&page=1" 2>/dev/null || echo '{}')
TOTAL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pagination',{}).get('total',0))" 2>/dev/null || echo 0)
if [ "$TOTAL" -gt 0 ]; then
    log_pass "List repositories with pagination (total: $TOTAL)"
else
    log_fail "List repositories returned empty"
fi

# ============================================================
log_section "Phase 2: Artifact Upload Across Formats"
# ============================================================

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

upload_generic() {
    local repo_key="$1"
    local name="$2"
    local size="${3:-1024}"
    dd if=/dev/urandom of="$WORK_DIR/$name" bs=1 count="$size" 2>/dev/null
    sleep "$RATE_DELAY"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "$REGISTRY_URL/api/v1/repositories/$repo_key/artifacts/$name" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$WORK_DIR/$name" 2>/dev/null)
    echo "$status"
}

# --- Generic uploads ---
GENERIC_KEY="stress-generic-local-${TIMESTAMP}"
for i in $(seq 1 10); do
    STATUS=$(upload_generic "$GENERIC_KEY" "artifact-v${i}.0.tar.gz" 4096)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        log_pass "Upload generic artifact #$i (4KB)"
    else
        log_fail "Upload generic artifact #$i: HTTP $STATUS"
    fi
done

# --- Large artifact upload ---
log_info "Uploading 5MB artifact..."
dd if=/dev/urandom of="$WORK_DIR/large-artifact.bin" bs=1M count=5 2>/dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/artifacts/large-artifact-5mb.bin" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/large-artifact.bin" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload 5MB artifact"
else
    log_fail "Upload 5MB artifact: HTTP $STATUS"
fi

# --- Maven artifact upload ---
MAVEN_KEY="stress-maven-local-${TIMESTAMP}"
# Create a minimal POM
cat > "$WORK_DIR/test-artifact-1.0.pom" << 'POMEOF'
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.stresstest</groupId>
  <artifactId>test-artifact</artifactId>
  <version>1.0</version>
</project>
POMEOF
echo "fake jar content" > "$WORK_DIR/test-artifact-1.0.jar"

# Upload POM (Maven format uses Basic auth on wire protocol)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/maven/$MAVEN_KEY/com/stresstest/test-artifact/1.0/test-artifact-1.0.pom" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/xml" \
    --data-binary "@$WORK_DIR/test-artifact-1.0.pom" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload Maven POM (wire protocol)"
else
    # Try via API endpoint
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "$REGISTRY_URL/api/v1/repositories/$MAVEN_KEY/artifacts/com/stresstest/test-artifact/1.0/test-artifact-1.0.pom" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/xml" \
        --data-binary "@$WORK_DIR/test-artifact-1.0.pom" 2>/dev/null)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        log_pass "Upload Maven POM (API endpoint)"
    else
        log_fail "Upload Maven POM: HTTP $STATUS (tried both wire protocol and API)"
    fi
fi

# Upload JAR
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/maven/$MAVEN_KEY/com/stresstest/test-artifact/1.0/test-artifact-1.0.jar" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@$WORK_DIR/test-artifact-1.0.jar" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload Maven JAR (wire protocol)"
else
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "$REGISTRY_URL/api/v1/repositories/$MAVEN_KEY/artifacts/com/stresstest/test-artifact/1.0/test-artifact-1.0.jar" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/java-archive" \
        --data-binary "@$WORK_DIR/test-artifact-1.0.jar" 2>/dev/null)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        log_pass "Upload Maven JAR (API endpoint)"
    else
        log_fail "Upload Maven JAR: HTTP $STATUS"
    fi
fi

# --- NPM package upload ---
NPM_KEY="stress-npm-local-${TIMESTAMP}"
cat > "$WORK_DIR/package.json" << EOF
{
  "name": "@stresstest/pkg",
  "version": "1.0.0",
  "description": "Stress test package"
}
EOF
echo "module.exports = {};" > "$WORK_DIR/index.js"
tar -czf "$WORK_DIR/stresstest-pkg-1.0.0.tgz" -C "$WORK_DIR" package.json index.js 2>/dev/null

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$NPM_KEY/artifacts/@stresstest/pkg/-/pkg-1.0.0.tgz" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/stresstest-pkg-1.0.0.tgz" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload NPM package"
else
    log_fail "Upload NPM package: HTTP $STATUS"
fi

# --- PyPI package upload ---
PYPI_KEY="stress-pypi-local-${TIMESTAMP}"
cat > "$WORK_DIR/setup.py" << 'EOF'
from setuptools import setup
setup(name='stress-test-pkg', version='1.0.0')
EOF
echo "# stress test" > "$WORK_DIR/stress_test_pkg.py"
tar -czf "$WORK_DIR/stress-test-pkg-1.0.0.tar.gz" -C "$WORK_DIR" setup.py stress_test_pkg.py 2>/dev/null

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$PYPI_KEY/artifacts/stress-test-pkg-1.0.0.tar.gz" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/stress-test-pkg-1.0.0.tar.gz" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload PyPI package"
else
    log_fail "Upload PyPI package: HTTP $STATUS"
fi

# --- Helm chart upload ---
HELM_KEY="stress-helm-local-${TIMESTAMP}"
mkdir -p "$WORK_DIR/stress-chart"
cat > "$WORK_DIR/stress-chart/Chart.yaml" << 'EOF'
apiVersion: v2
name: stress-chart
description: Stress test chart
version: 1.0.0
type: application
EOF
cat > "$WORK_DIR/stress-chart/values.yaml" << 'EOF'
replicaCount: 1
EOF
tar -czf "$WORK_DIR/stress-chart-1.0.0.tgz" -C "$WORK_DIR" stress-chart 2>/dev/null

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$HELM_KEY/artifacts/stress-chart-1.0.0.tgz" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/stress-chart-1.0.0.tgz" 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_pass "Upload Helm chart"
else
    log_fail "Upload Helm chart: HTTP $STATUS"
fi

# ============================================================
log_section "Phase 3: Artifact Download & Verification"
# ============================================================

# --- Download and verify checksum ---
ARTIFACT_RESP=$(api GET "/api/v1/repositories/$GENERIC_KEY/artifacts" 2>/dev/null || echo '{"items":[]}')
FIRST_ARTIFACT=$(echo "$ARTIFACT_RESP" | python3 -c "
import sys,json
items = json.load(sys.stdin).get('items',[])
if items:
    print(f\"{items[0]['path']}|{items[0]['checksum_sha256']}|{items[0]['id']}\")
else:
    print('NONE|NONE|NONE')
" 2>/dev/null)
ART_PATH="${FIRST_ARTIFACT%%|*}"
REMAINING="${FIRST_ARTIFACT#*|}"
ART_SHA="${REMAINING%%|*}"
ART_ID="${REMAINING#*|}"

if [ "$ART_PATH" != "NONE" ]; then
    curl -s "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/download/$ART_PATH" \
        -H "Authorization: Bearer $TOKEN" \
        -o "$WORK_DIR/downloaded-artifact" 2>/dev/null || true
    if [ -f "$WORK_DIR/downloaded-artifact" ]; then
        DL_SHA=$(shasum -a 256 "$WORK_DIR/downloaded-artifact" | cut -d' ' -f1)
        if [ "$DL_SHA" = "$ART_SHA" ]; then
            log_pass "Download + checksum verification matches"
        else
            log_fail "Checksum mismatch: expected=$ART_SHA got=$DL_SHA"
        fi
    else
        log_fail "Download artifact failed - no file produced"
    fi

    # --- Test: Download stats incremented ---
    STATS=$(api GET "/api/v1/artifacts/$ART_ID/stats" 2>/dev/null || echo '{}')
    DL_COUNT=$(echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('download_count', d.get('total_downloads', 0)))" 2>/dev/null || echo "0")
    if [ "$DL_COUNT" -gt 0 ]; then
        log_pass "Download count incremented (count: $DL_COUNT)"
    else
        log_warn "Download count may not have incremented: $DL_COUNT"
    fi
else
    log_fail "No artifacts found to download"
fi

# ============================================================
log_section "Phase 4: Staging & Promotion Workflow"
# ============================================================

STAGING_KEY="stress-generic-staging-${TIMESTAMP}"
RELEASE_KEY="stress-generic-local-${TIMESTAMP}"

# Upload artifacts to staging
for i in $(seq 1 5); do
    upload_generic "$STAGING_KEY" "staging-artifact-v${i}.tar.gz" 2048 >/dev/null
done
log_info "Uploaded 5 artifacts to staging repo"

# List staging artifacts
STAGING_ARTS=$(api GET "/api/v1/repositories/$STAGING_KEY/artifacts" 2>/dev/null || echo '{"items":[]}')
STAGING_COUNT=$(echo "$STAGING_ARTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo 0)
if [ "$STAGING_COUNT" -eq 5 ]; then
    log_pass "Staging repo has all 5 uploaded artifacts"
else
    log_fail "Staging repo artifact count: expected 5, got $STAGING_COUNT"
fi

# Try to promote each artifact
PROMO_SUCCESS=0
PROMO_FAIL=0
PROMO_ERRORS=()
PROMO_RESULTS=$(echo "$STAGING_ARTS" | python3 -c "
import sys, json
items = json.load(sys.stdin).get('items', [])
for item in items:
    print(item['id'])
" 2>/dev/null)

for aid in $PROMO_RESULTS; do
    RESP=$(api_full POST "/api/v1/promotion/repositories/$STAGING_KEY/artifacts/$aid/promote" \
        -d "{\"target_repository\":\"$RELEASE_KEY\",\"skip_policy_check\":true,\"notes\":\"Stress test promotion\"}")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
        ((PROMO_SUCCESS++)) || true
    else
        ((PROMO_FAIL++)) || true
        PROMO_ERRORS+=("$CODE: ${RESP#*|}")
    fi
done

if [ "$PROMO_SUCCESS" -gt 0 ]; then
    log_pass "Promotion succeeded: $PROMO_SUCCESS artifacts"
fi
if [ "$PROMO_FAIL" -gt 0 ]; then
    log_fail "Promotion failed: $PROMO_FAIL artifacts (${PROMO_ERRORS[0]:-unknown error})"
fi
if [ "$PROMO_SUCCESS" -eq 0 ] && [ "$PROMO_FAIL" -eq 0 ]; then
    log_warn "No promotions attempted"
fi

# --- Test: Promotion history ---
HIST=$(api GET "/api/v1/promotion/repositories/$STAGING_KEY/promotion-history" 2>/dev/null || echo '{"items":[]}')
HIST_COUNT=$(echo "$HIST" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('items', d if isinstance(d, list) else [])))" 2>/dev/null || echo 0)
log_info "Promotion history entries: $HIST_COUNT"

# ============================================================
log_section "Phase 5: Security Scanning"
# ============================================================

# --- Trigger scan on uploaded artifacts ---
SCAN_ARTIFACTS=$(api GET "/api/v1/repositories/$GENERIC_KEY/artifacts?per_page=3" 2>/dev/null || echo '{"items":[]}')
echo "$SCAN_ARTIFACTS" | python3 -c "
import sys, json
items = json.load(sys.stdin).get('items', [])
for item in items[:3]:
    print(item['id'])
" 2>/dev/null | while read -r aid; do
    RESP=$(api_full POST "/api/v1/security/scan" -d "{\"artifact_id\":\"$aid\"}")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "201" ] || [ "$CODE" = "202" ]; then
        log_pass "Triggered scan for artifact $aid"
    else
        log_warn "Scan trigger returned HTTP $CODE for $aid"
    fi
done

# --- Wait a moment for scans to process ---
log_info "Waiting 5s for scans to process..."
sleep 5

# --- Check security dashboard ---
DASHBOARD=$(api GET "/api/v1/security/dashboard" 2>/dev/null || echo '{}')
TOTAL_SCANS=$(echo "$DASHBOARD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_scans',0))" 2>/dev/null || echo 0)
log_info "Security dashboard: total_scans=$TOTAL_SCANS"

# --- Check scan results ---
SCANS=$(api GET "/api/v1/security/scans?per_page=5" 2>/dev/null || echo '{"items":[]}')
SCAN_LIST=$(echo "$SCANS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', data if isinstance(data, list) else [])
for s in items[:5]:
    sid = s.get('id', 'unknown')
    status = s.get('status', 'unknown')
    scanner = s.get('scanner_name', s.get('scanner', 'unknown'))
    print(f'{sid}|{status}|{scanner}')
" 2>/dev/null)
if [ -n "$SCAN_LIST" ]; then
    while IFS='|' read -r sid sstatus sscanner; do
        log_info "Scan $sid: status=$sstatus scanner=$sscanner"
    done <<< "$SCAN_LIST"
else
    log_info "No scan results found yet"
fi

# --- Test: Create security policy ---
POLICY_RESP=$(api_full POST "/api/v1/security/policies" -d '{
    "name":"stress-test-policy",
    "description":"Block critical CVEs",
    "rules":[{"severity":"critical","action":"block"},{"severity":"high","action":"warn"}],
    "enabled":true
}')
POLICY_CODE="${POLICY_RESP%%|*}"
if [ "$POLICY_CODE" = "200" ] || [ "$POLICY_CODE" = "201" ]; then
    log_pass "Create security policy"
    POLICY_ID=$(echo "${POLICY_RESP#*|}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
else
    log_warn "Create security policy: HTTP $POLICY_CODE (may already exist or different schema)"
fi

# ============================================================
log_section "Phase 6: Edge Cases & Error Handling"
# ============================================================

# --- Test: Empty repository key ---
RESP=$(api_full POST "/api/v1/repositories" -d '{"key":"","name":"Empty Key Test","format":"generic","repo_type":"local"}')
CODE="${RESP%%|*}"
if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
    log_pass "Empty repo key properly rejected (HTTP $CODE)"
elif [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    log_fail "Empty repo key was accepted - should be rejected"
else
    log_warn "Empty repo key: unexpected HTTP $CODE"
fi

# --- Test: Very long repository key (256+ chars) ---
LONG_KEY=$(python3 -c "print('a' * 300)")
RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$LONG_KEY\",\"name\":\"Long Key\",\"format\":\"generic\",\"repo_type\":\"local\"}")
CODE="${RESP%%|*}"
if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
    log_pass "Very long repo key rejected (HTTP $CODE)"
elif [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
    log_fail "300-char repo key was accepted - should have length limit"
    cleanup_repo "$LONG_KEY"
else
    log_warn "Long repo key: HTTP $CODE"
fi

# --- Test: Special characters in repo key ---
SPECIAL_KEYS=("test/../../../etc/passwd" "test; DROP TABLE repos;--" "test<script>alert(1)</script>" "test%00null" "test\nline")
for sk in "${SPECIAL_KEYS[@]}"; do
    RESP=$(api_full POST "/api/v1/repositories" -d "{\"key\":\"$sk\",\"name\":\"Special Chars\",\"format\":\"generic\",\"repo_type\":\"local\"}")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; then
        log_pass "Special key '$sk' properly rejected"
    elif [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; then
        log_fail "SECURITY: Special key '$sk' was accepted - possible injection vector"
    elif [ "$CODE" = "409" ]; then
        log_warn "Special key '$sk' already exists (from previous test?)"
    else
        log_info "Special key '$sk': HTTP $CODE"
    fi
done

# --- Test: Upload to non-existent repo ---
STATUS=$(upload_generic "nonexistent-repo-${TIMESTAMP}" "test.tar.gz" 100)
if [ "$STATUS" = "404" ]; then
    log_pass "Upload to non-existent repo returns 404"
elif [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_fail "Upload to non-existent repo succeeded - should be 404"
else
    log_info "Upload to non-existent repo: HTTP $STATUS"
fi

# --- Test: Upload zero-byte artifact ---
touch "$WORK_DIR/empty-file"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/artifacts/empty-file.bin" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$WORK_DIR/empty-file" 2>/dev/null)
if [ "$STATUS" = "400" ] || [ "$STATUS" = "422" ]; then
    log_pass "Zero-byte upload properly rejected (HTTP $STATUS)"
elif [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_warn "Zero-byte upload accepted (may be intentional for some formats)"
else
    log_info "Zero-byte upload: HTTP $STATUS"
fi

# --- Test: Upload with path traversal in artifact name ---
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/artifacts/../../../etc/passwd" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "malicious" 2>/dev/null)
if [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] || [ "$STATUS" = "422" ]; then
    log_pass "Path traversal in artifact name rejected (HTTP $STATUS)"
elif [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
    log_fail "SECURITY: Path traversal in artifact name was accepted!"
else
    log_info "Path traversal in artifact name: HTTP $STATUS"
fi

# --- Test: Delete artifact ---
if [ "${ART_ID:-NONE}" != "NONE" ] && [ -n "${ART_ID:-}" ]; then
    RESP=$(api_full DELETE "/api/v1/repositories/$GENERIC_KEY/artifacts/$ART_PATH")
    CODE="${RESP%%|*}"
    if [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; then
        log_pass "Delete artifact"
    else
        log_fail "Delete artifact: HTTP $CODE"
    fi
fi

# --- Test: Access without auth ---
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d '{"key":"unauth-test","name":"Unauth","format":"generic","repo_type":"local"}' 2>/dev/null)
if [ "$UNAUTH_STATUS" = "401" ] || [ "$UNAUTH_STATUS" = "403" ]; then
    log_pass "Unauthenticated write properly rejected (HTTP $UNAUTH_STATUS)"
elif [ "$UNAUTH_STATUS" = "200" ] || [ "$UNAUTH_STATUS" = "201" ]; then
    log_fail "SECURITY: Unauthenticated write succeeded!"
else
    log_info "Unauthenticated write: HTTP $UNAUTH_STATUS"
fi

# --- Test: Expired/invalid token ---
INVALID_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$REGISTRY_URL/api/v1/auth/me" \
    -H "Authorization: Bearer invalid.token.here" 2>/dev/null)
if [ "$INVALID_STATUS" = "401" ]; then
    log_pass "Invalid JWT token properly rejected"
else
    log_fail "Invalid JWT token returned HTTP $INVALID_STATUS (expected 401)"
fi

# ============================================================
log_section "Phase 7: Concurrent Operations"
# ============================================================

log_info "Running 20 concurrent uploads..."
CONCURRENT_PASS=0
CONCURRENT_FAIL=0
PIDS=()

for i in $(seq 1 20); do
    (
        dd if=/dev/urandom of="$WORK_DIR/concurrent-$i.bin" bs=1K count=50 2>/dev/null
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
            "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/artifacts/concurrent-artifact-$i.bin" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$WORK_DIR/concurrent-$i.bin" 2>/dev/null)
        echo "$STATUS" > "$RESULTS_DIR/concurrent-$i.status"
    ) &
    PIDS+=($!)
done

# Wait for all uploads
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Count results
for i in $(seq 1 20); do
    STATUS=$(cat "$RESULTS_DIR/concurrent-$i.status" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        ((CONCURRENT_PASS++)) || true
    else
        ((CONCURRENT_FAIL++)) || true
    fi
done

if [ "$CONCURRENT_PASS" -eq 20 ]; then
    log_pass "All 20 concurrent uploads succeeded"
elif [ "$CONCURRENT_PASS" -gt 15 ]; then
    log_warn "Concurrent uploads: $CONCURRENT_PASS/20 passed ($CONCURRENT_FAIL failed)"
else
    log_fail "Concurrent uploads: only $CONCURRENT_PASS/20 passed"
fi

# --- Concurrent reads ---
log_info "Running 20 concurrent downloads..."
READ_PASS=0
READ_FAIL=0
PIDS=()

for i in $(seq 1 20); do
    (
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            "$REGISTRY_URL/api/v1/repositories/$GENERIC_KEY/artifacts" \
            -H "Authorization: Bearer $TOKEN" 2>/dev/null)
        echo "$STATUS" > "$RESULTS_DIR/read-$i.status"
    ) &
    PIDS+=($!)
done

for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

for i in $(seq 1 20); do
    STATUS=$(cat "$RESULTS_DIR/read-$i.status" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        ((READ_PASS++)) || true
    else
        ((READ_FAIL++)) || true
    fi
done

if [ "$READ_PASS" -eq 20 ]; then
    log_pass "All 20 concurrent reads succeeded"
else
    log_fail "Concurrent reads: $READ_PASS/20 passed"
fi

# ============================================================
log_section "Phase 8: Search & Discovery"
# ============================================================

# --- Quick search ---
SEARCH_RESP=$(api GET "/api/v1/search/quick?q=stress" 2>/dev/null || echo '{}')
SEARCH_COUNT=$(echo "$SEARCH_RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', data.get('results', data.get('hits', [])))
if isinstance(items, list):
    print(len(items))
else:
    print(0)
" 2>/dev/null || echo 0)
if [ "$SEARCH_COUNT" -gt 0 ]; then
    log_pass "Quick search returned $SEARCH_COUNT results for 'stress'"
else
    log_warn "Quick search returned 0 results (indexing may be async)"
fi

# --- Recent artifacts ---
RECENT=$(api GET "/api/v1/search/recent?limit=5" 2>/dev/null || echo '{}')
RECENT_COUNT=$(echo "$RECENT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', data.get('results', []))
if isinstance(items, list):
    print(len(items))
else:
    print(0)
" 2>/dev/null || echo 0)
if [ "$RECENT_COUNT" -gt 0 ]; then
    log_pass "Recent artifacts returned $RECENT_COUNT items"
else
    log_warn "Recent artifacts returned 0 items"
fi

# ============================================================
log_section "Phase 9: Admin & System Operations"
# ============================================================

# --- System stats ---
STATS=$(api GET "/api/v1/admin/stats" 2>/dev/null || echo '{}')
if echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d) > 0" 2>/dev/null; then
    log_pass "System stats endpoint works"
else
    log_fail "System stats returned empty"
fi

# --- Storage analytics ---
STORAGE=$(api GET "/api/v1/admin/analytics/storage" 2>/dev/null || echo '{}')
if echo "$STORAGE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    log_pass "Storage analytics endpoint works"
else
    log_fail "Storage analytics endpoint failed"
fi

# --- Lifecycle policy ---
LC_RESP=$(api_full POST "/api/v1/admin/lifecycle" -d '{
    "name":"stress-test-retention",
    "description":"Delete artifacts older than 30 days",
    "repository_key":"'"$GENERIC_KEY"'",
    "rules":[{"type":"age","max_age_days":30}],
    "enabled":false
}')
LC_CODE="${LC_RESP%%|*}"
if [ "$LC_CODE" = "200" ] || [ "$LC_CODE" = "201" ]; then
    log_pass "Create lifecycle policy"
    LC_ID=$(echo "${LC_RESP#*|}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
    if [ -n "$LC_ID" ]; then
        # Preview (dry-run)
        PREVIEW=$(api_full POST "/api/v1/admin/lifecycle/$LC_ID/preview")
        PREVIEW_CODE="${PREVIEW%%|*}"
        if [ "$PREVIEW_CODE" = "200" ]; then
            log_pass "Lifecycle policy preview (dry-run)"
        else
            log_warn "Lifecycle policy preview: HTTP $PREVIEW_CODE"
        fi
    fi
else
    log_warn "Create lifecycle policy: HTTP $LC_CODE"
fi

# --- Backup ---
BACKUP_RESP=$(api_full POST "/api/v1/admin/backups" -d '{"type":"metadata","description":"stress test backup"}')
BACKUP_CODE="${BACKUP_RESP%%|*}"
if [ "$BACKUP_CODE" = "200" ] || [ "$BACKUP_CODE" = "201" ] || [ "$BACKUP_CODE" = "202" ]; then
    log_pass "Create metadata backup"
else
    log_warn "Create backup: HTTP $BACKUP_CODE"
fi

# ============================================================
log_section "Phase 10: Webhook & Event System"
# ============================================================

WEBHOOK_RESP=$(api_full POST "/api/v1/webhooks" -d '{
    "url":"https://httpbin.org/post",
    "events":["artifact.uploaded","artifact.promoted"],
    "repository_key":"'"$GENERIC_KEY"'",
    "enabled":true
}')
WH_CODE="${WEBHOOK_RESP%%|*}"
if [ "$WH_CODE" = "200" ] || [ "$WH_CODE" = "201" ]; then
    log_pass "Create webhook"
    WH_ID=$(echo "${WEBHOOK_RESP#*|}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
    if [ -n "$WH_ID" ]; then
        # Test webhook delivery
        TEST_RESP=$(api_full POST "/api/v1/webhooks/$WH_ID/test")
        TEST_CODE="${TEST_RESP%%|*}"
        if [ "$TEST_CODE" = "200" ] || [ "$TEST_CODE" = "201" ]; then
            log_pass "Webhook test delivery"
        else
            log_warn "Webhook test: HTTP $TEST_CODE"
        fi
    fi
else
    log_warn "Create webhook: HTTP $WH_CODE"
fi

# ============================================================
log_section "Phase 11: User & Permission Management"
# ============================================================

# --- Create test user ---
USER_RESP=$(api_full POST "/api/v1/users" -d '{
    "username":"stress-test-user",
    "email":"stress@test.local",
    "password":"TestPass123!",
    "display_name":"Stress Test User"
}')
USER_CODE="${USER_RESP%%|*}"
if [ "$USER_CODE" = "200" ] || [ "$USER_CODE" = "201" ]; then
    log_pass "Create test user"
    TEST_USER_ID=$(echo "${USER_RESP#*|}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
else
    log_warn "Create test user: HTTP $USER_CODE (may already exist)"
fi

# --- Test: Login as new user ---
NEW_TOKEN_RESP=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"stress-test-user","password":"TestPass123!"}' 2>/dev/null || echo '{}')
if echo "$NEW_TOKEN_RESP" | python3 -c "import sys,json; assert json.load(sys.stdin).get('access_token')" 2>/dev/null; then
    log_pass "Login as new user"
else
    log_warn "Login as new user failed"
fi

# --- Create API token ---
if [ -n "${TEST_USER_ID:-}" ]; then
    API_TOKEN_RESP=$(api_full POST "/api/v1/users/$TEST_USER_ID/tokens" -d '{"name":"stress-test-token","expires_in_days":1}')
    AT_CODE="${API_TOKEN_RESP%%|*}"
    if [ "$AT_CODE" = "200" ] || [ "$AT_CODE" = "201" ]; then
        log_pass "Create API token for user"
    else
        log_warn "Create API token: HTTP $AT_CODE"
    fi
fi

# ============================================================
log_section "Phase 12: SBOM & License Compliance"
# ============================================================

# --- Generate SBOM for an artifact ---
if [ "${ART_ID:-NONE}" != "NONE" ] && [ -n "${ART_ID:-}" ]; then
    SBOM_RESP=$(api_full POST "/api/v1/sbom" -d "{\"artifact_id\":\"$ART_ID\",\"format\":\"cyclonedx\"}")
    SBOM_CODE="${SBOM_RESP%%|*}"
    if [ "$SBOM_CODE" = "200" ] || [ "$SBOM_CODE" = "201" ] || [ "$SBOM_CODE" = "202" ]; then
        log_pass "Generate SBOM (CycloneDX)"
    else
        log_info "SBOM generation: HTTP $SBOM_CODE (may require scannable artifact)"
    fi
fi

# ============================================================
log_section "Results Summary"
# ============================================================

TOTAL=$((PASS + FAIL + WARN))

echo ""
echo -e "${GREEN}PASSED:  $PASS${NC}"
echo -e "${RED}FAILED:  $FAIL${NC}"
echo -e "${YELLOW}WARNINGS: $WARN${NC}"
echo -e "TOTAL:   $TOTAL"
echo ""

if [ ${#BUGS[@]} -gt 0 ]; then
    echo -e "${RED}Bugs Found:${NC}"
    for bug in "${BUGS[@]}"; do
        echo -e "  - $bug"
    done
fi

# Write results JSON
cat > "$RESULTS_DIR/stress-test-summary-${TIMESTAMP}.json" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "registry_url": "$REGISTRY_URL",
    "results": {
        "passed": $PASS,
        "failed": $FAIL,
        "warnings": $WARN,
        "total": $TOTAL
    },
    "bugs": $(python3 -c "import json; print(json.dumps([$(printf '"%s",' "${BUGS[@]}" | sed 's/,$//')]))" 2>/dev/null || echo "[]")
}
EOF

echo ""
echo "Results saved to: $RESULTS_DIR/stress-test-summary-${TIMESTAMP}.json"

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
