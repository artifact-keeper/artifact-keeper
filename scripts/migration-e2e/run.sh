#!/usr/bin/env bash
#
# E2E Migration Test: Artifactory OSS + Nexus OSS -> Artifact Keeper
#
# Tests the full migration pipeline:
#   1. Spins up Artifactory OSS + Nexus OSS + Artifact Keeper
#   2. Seeds both with Maven artifacts
#   3. Creates migration connections and jobs
#   4. Runs the migrations
#   5. Verifies artifacts were transferred correctly
#
# Usage:
#   ./scripts/migration-e2e/run.sh          # Run full test
#   ./scripts/migration-e2e/run.sh --clean  # Cleanup only

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f ${SCRIPT_DIR}/docker-compose.yml -p migration-e2e"

AK_URL="http://localhost:18080"
AF_URL="http://localhost:18081"
AF_ROUTER="http://localhost:18082"
AF_USER="admin"
AF_PASS="password"

PASSED=0
FAILED=0
TOTAL=0

# --- Helpers ---

log() { echo -e "${BLUE}[migration-e2e]${NC} $*"; }
pass() { ((PASSED++)); ((TOTAL++)); echo -e "  ${GREEN}✓${NC} $*"; }
fail() { ((FAILED++)); ((TOTAL++)); echo -e "  ${RED}✗${NC} $*"; }

cleanup() {
    log "Cleaning up containers..."
    $COMPOSE down -v --remove-orphans 2>/dev/null || true
}

wait_for_service() {
    local name=$1 url=$2 max_attempts=${3:-60}
    log "Waiting for ${name}..."
    for i in $(seq 1 "$max_attempts"); do
        if curl -sf "$url" > /dev/null 2>&1; then
            log "${name} is ready (attempt ${i})"
            return 0
        fi
        sleep 3
    done
    fail "${name} failed to start after ${max_attempts} attempts"
    return 1
}

ak_api() {
    local method=$1 path=$2
    shift 2
    curl -sf -X "$method" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AK_TOKEN}" \
        "${AK_URL}${path}" "$@"
}

# --- Parse args ---

if [[ "${1:-}" == "--clean" ]]; then
    cleanup
    exit 0
fi

trap cleanup EXIT

# --- Step 0: Start services ---

log "Starting services..."
cleanup
$COMPOSE up -d --build

wait_for_service "Artifact Keeper" "${AK_URL}/health" 60
wait_for_service "Artifactory" "${AF_ROUTER}/router/api/v1/system/health" 90

# --- Step 1: Get AK auth token ---

log "Authenticating with Artifact Keeper..."
AK_TOKEN=$(curl -sf -X POST "${AK_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}' | jq -r '.token // .access_token // empty')

if [[ -z "$AK_TOKEN" ]]; then
    # Try default first-boot token endpoint
    AK_TOKEN=$(curl -sf -X POST "${AK_URL}/api/v1/auth/token" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin"}' | jq -r '.token // .access_token // empty')
fi

if [[ -z "$AK_TOKEN" ]]; then
    fail "Failed to authenticate with Artifact Keeper"
    exit 1
fi
pass "Authenticated with Artifact Keeper"

# ============================================================
# PHASE 1: Artifactory OSS Migration
# ============================================================

log ""
log "═══════════════════════════════════════════"
log "  Phase 1: Artifactory OSS Migration"
log "═══════════════════════════════════════════"

# Artifactory OSS comes with a default "example-repo-local" repository.
# The REST API for creating repositories is Pro-only, so we use the default repo.
AF_REPO="example-repo-local"

log "Seeding Artifactory with test data..."
sleep 5

# Generate test Maven artifacts
SEED_DIR=$(mktemp -d)

echo "PK fake-jar-content-for-testing-migration" > "${SEED_DIR}/myapp-1.0.0.jar"
cat > "${SEED_DIR}/myapp-1.0.0.pom" << 'POMEOF'
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
</project>
POMEOF
echo "PK fake-jar-content-v2-for-testing" > "${SEED_DIR}/myapp-2.0.0.jar"
echo "PK utils-library-content" > "${SEED_DIR}/utils-1.0.0.jar"

# Upload artifacts to the default repo via PUT (works in OSS)
for artifact in "com/example/myapp/1.0.0/myapp-1.0.0.jar" \
                "com/example/myapp/1.0.0/myapp-1.0.0.pom" \
                "com/example/myapp/2.0.0/myapp-2.0.0.jar" \
                "org/example/utils/1.0.0/utils-1.0.0.jar"; do
    filename=$(basename "$artifact")
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${AF_USER}:${AF_PASS}" \
        -T "${SEED_DIR}/${filename}" \
        "${AF_URL}/artifactory/${AF_REPO}/${artifact}")
    if [[ "$HTTP_CODE" == "201" ]]; then
        pass "Uploaded ${artifact}"
    else
        fail "Failed to upload ${artifact} (HTTP ${HTTP_CODE})"
    fi
done

rm -rf "$SEED_DIR"

# Verify artifacts are in Artifactory via AQL
ARTIFACT_COUNT=$(curl -sf -u "${AF_USER}:${AF_PASS}" \
    -X POST \
    -H "Content-Type: text/plain" \
    -d "items.find({\"repo\":\"${AF_REPO}\",\"type\":\"file\"})" \
    "${AF_URL}/artifactory/api/search/aql" | jq '.results | length')

log "Artifactory has ${ARTIFACT_COUNT} artifacts in ${AF_REPO}"
if [[ "$ARTIFACT_COUNT" -ge 4 ]]; then
    pass "Artifactory seeded with ${ARTIFACT_COUNT} artifacts"
else
    fail "Expected at least 4 artifacts, got ${ARTIFACT_COUNT}"
fi

# --- Create migration connection in Artifact Keeper ---

log "Creating Artifactory migration connection..."
CONNECTION_RESPONSE=$(ak_api POST "/api/v1/migrations/connections" \
    -d "{
        \"name\": \"test-artifactory\",
        \"url\": \"http://artifactory:8081/artifactory\",
        \"auth_type\": \"basic_auth\",
        \"source_type\": \"artifactory\",
        \"credentials\": {
            \"username\": \"${AF_USER}\",
            \"password\": \"${AF_PASS}\"
        }
    }")

CONNECTION_ID=$(echo "$CONNECTION_RESPONSE" | jq -r '.id // empty')
if [[ -n "$CONNECTION_ID" ]]; then
    pass "Created migration connection: ${CONNECTION_ID}"
else
    fail "Failed to create migration connection"
    echo "$CONNECTION_RESPONSE"
    exit 1
fi

# Test the connection
TEST_RESULT=$(ak_api POST "/api/v1/migrations/connections/${CONNECTION_ID}/test" || echo '{"error":"failed"}')
if echo "$TEST_RESULT" | jq -e '.version // .success' > /dev/null 2>&1; then
    pass "Connection test passed"
else
    log "${YELLOW}Connection test response: ${TEST_RESULT}${NC}"
fi

# List source repositories
REPOS=$(ak_api GET "/api/v1/migrations/connections/${CONNECTION_ID}/repositories" || echo '{"items":[]}')
REPO_COUNT=$(echo "$REPOS" | jq '.items // . | length')
log "Found ${REPO_COUNT} repositories in source Artifactory"

# --- Create and start migration job ---

log "Creating migration job..."
JOB_RESPONSE=$(ak_api POST "/api/v1/migrations" \
    -d "{
        \"source_connection_id\": \"${CONNECTION_ID}\",
        \"job_type\": \"full\",
        \"config\": {
            \"include_repos\": [\"${AF_REPO}\"],
            \"conflict_resolution\": \"skip\",
            \"concurrent_transfers\": 2,
            \"throttle_delay_ms\": 50,
            \"dry_run\": false
        }
    }")

JOB_ID=$(echo "$JOB_RESPONSE" | jq -r '.id // empty')
if [[ -n "$JOB_ID" ]]; then
    pass "Created migration job: ${JOB_ID}"
else
    fail "Failed to create migration job"
    echo "$JOB_RESPONSE"
    exit 1
fi

# Start the migration
log "Starting migration..."
START_RESPONSE=$(ak_api POST "/api/v1/migrations/${JOB_ID}/start")
START_STATUS=$(echo "$START_RESPONSE" | jq -r '.status // empty')
if [[ "$START_STATUS" == "running" ]]; then
    pass "Migration started"
else
    fail "Migration failed to start (status: ${START_STATUS})"
    echo "$START_RESPONSE"
fi

# --- Poll for completion ---

log "Waiting for migration to complete..."
MAX_WAIT=120
ELAPSED=0
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    POLL_RESULT=$(ak_api GET "/api/v1/migrations/${JOB_ID}")
    JOB_STATUS=$(echo "$POLL_RESULT" | jq -r '.status')
    COMPLETED=$(echo "$POLL_RESULT" | jq -r '.completed_items // 0')
    FAILED_ITEMS=$(echo "$POLL_RESULT" | jq -r '.failed_items // 0')

    if [[ "$JOB_STATUS" == "completed" || "$JOB_STATUS" == "failed" ]]; then
        break
    fi

    log "  Status: ${JOB_STATUS} | Completed: ${COMPLETED} | Failed: ${FAILED_ITEMS} (${ELAPSED}s)"
    sleep 5
    ((ELAPSED += 5))
done

# --- Verify results ---

log "Checking Artifactory migration results..."
FINAL_JOB=$(ak_api GET "/api/v1/migrations/${JOB_ID}")
FINAL_STATUS=$(echo "$FINAL_JOB" | jq -r '.status')
FINAL_COMPLETED=$(echo "$FINAL_JOB" | jq -r '.completed_items // 0')
FINAL_FAILED=$(echo "$FINAL_JOB" | jq -r '.failed_items // 0')
FINAL_SKIPPED=$(echo "$FINAL_JOB" | jq -r '.skipped_items // 0')

log "Migration result: status=${FINAL_STATUS} completed=${FINAL_COMPLETED} failed=${FINAL_FAILED} skipped=${FINAL_SKIPPED}"

if [[ "$FINAL_STATUS" == "completed" ]]; then
    pass "Artifactory migration completed successfully"
else
    fail "Artifactory migration ended with status: ${FINAL_STATUS}"
    ERROR=$(echo "$FINAL_JOB" | jq -r '.error_summary // empty')
    [[ -n "$ERROR" ]] && log "${RED}Error: ${ERROR}${NC}"
fi

if [[ "$FINAL_COMPLETED" -ge 3 ]]; then
    pass "Migrated ${FINAL_COMPLETED} artifacts from Artifactory"
else
    fail "Expected at least 3 completed artifacts, got ${FINAL_COMPLETED}"
fi

if [[ "$FINAL_FAILED" -eq 0 ]]; then
    pass "No failed artifacts"
else
    fail "${FINAL_FAILED} artifacts failed"
    ITEMS=$(ak_api GET "/api/v1/migrations/${JOB_ID}/items?status=failed" || echo '{}')
    echo "$ITEMS" | jq '.items[]? | {source_path, error_message}' 2>/dev/null || true
fi

# Check that artifacts exist in AK
AK_ARTIFACTS_RESP=$(curl -s "${AK_URL}/api/v1/artifacts?limit=100" \
    -H "Authorization: Bearer ${AK_TOKEN}" || echo '[]')
AK_ARTIFACTS=$(echo "$AK_ARTIFACTS_RESP" | jq '.items // . | length' 2>/dev/null || echo "0")
log "Artifact Keeper has ${AK_ARTIFACTS} artifacts after Artifactory migration"

# ============================================================
# PHASE 2: Nexus OSS Migration
# ============================================================

log ""
log "═══════════════════════════════════════════"
log "  Phase 2: Nexus OSS Migration"
log "═══════════════════════════════════════════"

NX_URL="http://localhost:18083"
NX_USER="admin"
NX_PASS=""

wait_for_service "Nexus" "${NX_URL}/service/rest/v1/status" 90

# Get Nexus admin password from admin.password file (always written on first boot).
# The NEXUS_SECURITY_INITIAL_PASSWORD env var is unreliable across versions, so
# always read the file first, then change to our known password.
log "Retrieving Nexus admin password..."
NX_PASS=""
for attempt in $(seq 1 20); do
    NX_PASS=$(docker exec migration-e2e-nexus cat /nexus-data/admin.password 2>/dev/null || echo "")
    if [[ -n "$NX_PASS" ]]; then
        break
    fi
    sleep 3
done
if [[ -z "$NX_PASS" ]]; then
    fail "Could not read Nexus admin.password file"
else
    pass "Nexus admin password retrieved from admin.password"
fi

# Change admin password to a known value. This also signals to Nexus that the
# setup wizard is complete, which removes the admin.password file and unlocks
# full write access to repositories.
NX_NEW_PASS="nexus123"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${NX_USER}:${NX_PASS}" \
    -X PUT \
    -H "Content-Type: text/plain" \
    -d "${NX_NEW_PASS}" \
    "${NX_URL}/service/rest/v1/security/users/admin/change-password")
if [[ "$HTTP_CODE" == "204" || "$HTTP_CODE" == "200" ]]; then
    NX_PASS="${NX_NEW_PASS}"
    pass "Nexus admin password changed successfully"
else
    fail "Password change failed with HTTP ${HTTP_CODE}"
fi

# Accept the EULA — Nexus 3.77+ requires this before any write operations.
# GET the current EULA, flip accepted to true, POST it back.
EULA_JSON=$(curl -sf -u "${NX_USER}:${NX_PASS}" "${NX_URL}/service/rest/v1/system/eula" || echo "")
if [[ -n "$EULA_JSON" ]]; then
    ACCEPTED_JSON=$(echo "$EULA_JSON" | jq '.accepted = true')
    HTTP_CODE=$(echo "$ACCEPTED_JSON" | curl -s -o /dev/null -w "%{http_code}" \
        -u "${NX_USER}:${NX_PASS}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d @- \
        "${NX_URL}/service/rest/v1/system/eula")
    if [[ "$HTTP_CODE" == "204" ]]; then
        pass "Nexus EULA accepted"
    else
        log "${YELLOW}EULA acceptance returned HTTP ${HTTP_CODE}${NC}"
    fi
fi

# Enable anonymous access so the connection test doesn't need auth for status endpoint
curl -s -o /dev/null -u "${NX_USER}:${NX_PASS}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"enabled":true,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' \
    "${NX_URL}/service/rest/v1/security/anonymous" 2>/dev/null || true

# --- Seed Nexus with Maven artifacts ---

log "Seeding Nexus with test data..."

# Nexus comes with maven-releases and maven-snapshots by default.
# Create a custom hosted Maven repo for testing.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${NX_USER}:${NX_PASS}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "name": "nexus-maven-test",
        "online": true,
        "storage": {"blobStoreName": "default", "strictContentTypeValidation": false, "writePolicy": "ALLOW"},
        "maven": {"versionPolicy": "RELEASE", "layoutPolicy": "STRICT"}
    }' \
    "${NX_URL}/service/rest/v1/repositories/maven/hosted")

if [[ "$HTTP_CODE" == "201" || "$HTTP_CODE" == "204" ]]; then
    pass "Created Nexus nexus-maven-test repository"
else
    log "${YELLOW}Nexus repo creation returned HTTP ${HTTP_CODE} (may already exist or need EULA)${NC}"
fi

# Upload Maven artifacts to Nexus using the Components REST API.
# This is the official upload method and works reliably after setup wizard completion.
NX_SEED_DIR=$(mktemp -d)
echo "PK nexus-jar-content" > "${NX_SEED_DIR}/nexus-app-1.0.0.jar"
echo "PK nexus-jar-v2" > "${NX_SEED_DIR}/nexus-app-2.0.0.jar"
cat > "${NX_SEED_DIR}/nexus-app-1.0.0.pom" << 'POMEOF'
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.nexustest</groupId>
    <artifactId>nexus-app</artifactId>
    <version>1.0.0</version>
</project>
POMEOF

# Upload v1.0.0 JAR + POM as a single component
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${NX_USER}:${NX_PASS}" \
    -X POST \
    -F "maven2.groupId=com.nexustest" \
    -F "maven2.artifactId=nexus-app" \
    -F "maven2.version=1.0.0" \
    -F "maven2.asset1=@${NX_SEED_DIR}/nexus-app-1.0.0.jar" \
    -F "maven2.asset1.extension=jar" \
    -F "maven2.asset2=@${NX_SEED_DIR}/nexus-app-1.0.0.pom" \
    -F "maven2.asset2.extension=pom" \
    "${NX_URL}/service/rest/v1/components?repository=nexus-maven-test")
if [[ "$HTTP_CODE" == "204" ]]; then
    pass "Uploaded nexus-app 1.0.0 (jar+pom) to Nexus"
else
    fail "Failed to upload nexus-app 1.0.0 to Nexus (HTTP ${HTTP_CODE})"
fi

# Upload v2.0.0 JAR
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${NX_USER}:${NX_PASS}" \
    -X POST \
    -F "maven2.groupId=com.nexustest" \
    -F "maven2.artifactId=nexus-app" \
    -F "maven2.version=2.0.0" \
    -F "maven2.asset1=@${NX_SEED_DIR}/nexus-app-2.0.0.jar" \
    -F "maven2.asset1.extension=jar" \
    "${NX_URL}/service/rest/v1/components?repository=nexus-maven-test")
if [[ "$HTTP_CODE" == "204" ]]; then
    pass "Uploaded nexus-app 2.0.0 (jar) to Nexus"
else
    fail "Failed to upload nexus-app 2.0.0 to Nexus (HTTP ${HTTP_CODE})"
fi

rm -rf "$NX_SEED_DIR"

# --- Create Nexus migration connection ---

log "Creating Nexus migration connection..."
NX_CONN_RESPONSE=$(ak_api POST "/api/v1/migrations/connections" \
    -d "{
        \"name\": \"test-nexus\",
        \"url\": \"http://nexus:8081\",
        \"auth_type\": \"basic_auth\",
        \"source_type\": \"nexus\",
        \"credentials\": {
            \"username\": \"${NX_USER}\",
            \"password\": \"${NX_PASS}\"
        }
    }")

NX_CONN_ID=$(echo "$NX_CONN_RESPONSE" | jq -r '.id // empty')
if [[ -n "$NX_CONN_ID" ]]; then
    pass "Created Nexus migration connection: ${NX_CONN_ID}"
else
    fail "Failed to create Nexus migration connection"
    echo "$NX_CONN_RESPONSE"
fi

# Test Nexus connection
NX_TEST=$(ak_api POST "/api/v1/migrations/connections/${NX_CONN_ID}/test" || echo '{"error":"failed"}')
if echo "$NX_TEST" | jq -e '.version // .success' > /dev/null 2>&1; then
    pass "Nexus connection test passed"
else
    log "${YELLOW}Nexus test response: ${NX_TEST}${NC}"
fi

# --- Create and start Nexus migration job ---

log "Creating Nexus migration job..."
NX_JOB_RESPONSE=$(ak_api POST "/api/v1/migrations" \
    -d "{
        \"source_connection_id\": \"${NX_CONN_ID}\",
        \"job_type\": \"full\",
        \"config\": {
            \"include_repos\": [\"nexus-maven-test\"],
            \"conflict_resolution\": \"skip\",
            \"concurrent_transfers\": 2,
            \"throttle_delay_ms\": 50,
            \"dry_run\": false
        }
    }")

NX_JOB_ID=$(echo "$NX_JOB_RESPONSE" | jq -r '.id // empty')
if [[ -n "$NX_JOB_ID" ]]; then
    pass "Created Nexus migration job: ${NX_JOB_ID}"
else
    fail "Failed to create Nexus migration job"
    echo "$NX_JOB_RESPONSE"
fi

# Start migration
log "Starting Nexus migration..."
NX_START=$(ak_api POST "/api/v1/migrations/${NX_JOB_ID}/start")
NX_START_STATUS=$(echo "$NX_START" | jq -r '.status // empty')
if [[ "$NX_START_STATUS" == "running" ]]; then
    pass "Nexus migration started"
else
    fail "Nexus migration failed to start (status: ${NX_START_STATUS})"
fi

# Poll for completion
log "Waiting for Nexus migration to complete..."
ELAPSED=0
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    NX_POLL=$(ak_api GET "/api/v1/migrations/${NX_JOB_ID}")
    NX_STATUS=$(echo "$NX_POLL" | jq -r '.status')
    NX_COMPLETED=$(echo "$NX_POLL" | jq -r '.completed_items // 0')
    NX_FAILED_ITEMS=$(echo "$NX_POLL" | jq -r '.failed_items // 0')

    if [[ "$NX_STATUS" == "completed" || "$NX_STATUS" == "failed" ]]; then
        break
    fi

    log "  Status: ${NX_STATUS} | Completed: ${NX_COMPLETED} | Failed: ${NX_FAILED_ITEMS} (${ELAPSED}s)"
    sleep 5
    ((ELAPSED += 5))
done

# Verify Nexus results
NX_FINAL=$(ak_api GET "/api/v1/migrations/${NX_JOB_ID}")
NX_FINAL_STATUS=$(echo "$NX_FINAL" | jq -r '.status')
NX_FINAL_COMPLETED=$(echo "$NX_FINAL" | jq -r '.completed_items // 0')
NX_FINAL_FAILED=$(echo "$NX_FINAL" | jq -r '.failed_items // 0')

log "Nexus migration result: status=${NX_FINAL_STATUS} completed=${NX_FINAL_COMPLETED} failed=${NX_FINAL_FAILED}"

if [[ "$NX_FINAL_STATUS" == "completed" ]]; then
    pass "Nexus migration completed successfully"
else
    fail "Nexus migration ended with status: ${NX_FINAL_STATUS}"
fi

if [[ "$NX_FINAL_COMPLETED" -ge 2 ]]; then
    pass "Migrated ${NX_FINAL_COMPLETED} artifacts from Nexus"
else
    fail "Expected at least 2 completed Nexus artifacts, got ${NX_FINAL_COMPLETED}"
fi

# --- Final Summary ---

# Total artifacts in AK
TOTAL_RESP=$(curl -s "${AK_URL}/api/v1/artifacts?limit=100" \
    -H "Authorization: Bearer ${AK_TOKEN}" || echo '[]')
TOTAL_ARTIFACTS=$(echo "$TOTAL_RESP" | jq '.items // . | length' 2>/dev/null || echo "0")
log "Total artifacts in Artifact Keeper: ${TOTAL_ARTIFACTS}"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}  Migration E2E Test Results${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "  Total:  ${TOTAL}"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
echo -e "  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
