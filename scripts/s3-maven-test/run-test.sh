#!/bin/bash
# Maven S3 integration test - reproduces issue #361
# Tests full mvn deploy cycle against S3-backed storage (MinIO)
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://backend:8080}"
REGISTRY_USER="${REGISTRY_USER:-admin}"
REGISTRY_PASS="${REGISTRY_PASS:-admin}"
RUN_ID="$(date +%s)"
PASSED=0
FAILED=0

pass() { PASSED=$((PASSED + 1)); echo "  PASS: $1"; }
fail() { FAILED=$((FAILED + 1)); echo "  FAIL: $1"; }

echo "=============================================="
echo "Maven + S3 Storage Integration Test"
echo "=============================================="
echo "Registry: $REGISTRY_URL"
echo "Run ID:   $RUN_ID"
echo ""

# Wait for backend to be ready
echo "==> Waiting for backend..."
for i in $(seq 1 30); do
    if curl -sf "$REGISTRY_URL/health" > /dev/null 2>&1; then
        echo "Backend is ready"
        break
    fi
    if [ "$i" = "30" ]; then
        echo "FATAL: Backend did not become ready"
        exit 1
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# Step 1: Create a hosted Maven repository via API
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 1: Creating hosted Maven repository..."
REPO_KEY="maven-s3-test-${RUN_ID}"

CREATE_RESP=$(curl -s -w "\n%{http_code}" -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    -d "{
        \"key\": \"${REPO_KEY}\",
        \"name\": \"Maven S3 Test ${RUN_ID}\",
        \"description\": \"Test repo for Maven S3 integration (issue #361)\",
        \"format\": \"maven\",
        \"repo_type\": \"hosted\",
        \"storage_backend\": \"s3\"
    }")

HTTP_CODE=$(echo "$CREATE_RESP" | tail -1)
BODY=$(echo "$CREATE_RESP" | head -n -1)

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    pass "Created Maven repository: $REPO_KEY (HTTP $HTTP_CODE)"
else
    echo "Response: $BODY"
    fail "Failed to create Maven repository (HTTP $HTTP_CODE)"
    echo ""
    echo "Trying with default storage backend..."
    CREATE_RESP=$(curl -s -w "\n%{http_code}" -X POST "$REGISTRY_URL/api/v1/repositories" \
        -H "Content-Type: application/json" \
        -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
        -d "{
            \"key\": \"${REPO_KEY}\",
            \"name\": \"Maven S3 Test ${RUN_ID}\",
            \"description\": \"Test repo for Maven S3 integration (issue #361)\",
            \"format\": \"maven\",
            \"repo_type\": \"hosted\"
        }")
    HTTP_CODE=$(echo "$CREATE_RESP" | tail -1)
    BODY=$(echo "$CREATE_RESP" | head -n -1)
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        pass "Created Maven repository with default backend: $REPO_KEY (HTTP $HTTP_CODE)"
    else
        echo "Response: $BODY"
        fail "Failed to create Maven repository with default backend (HTTP $HTTP_CODE)"
        echo ""
        echo "FATAL: Cannot proceed without a repository"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: Test RELEASE artifact deploy via mvn deploy
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 2: Testing RELEASE artifact deploy..."

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

RELEASE_VERSION="1.0.${RUN_ID}"
MAVEN_REPO_URL="${REGISTRY_URL}/maven/${REPO_KEY}"

# Generate test project
mkdir -p src/main/java/com/test
cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test.s3</groupId>
    <artifactId>s3-test-artifact</artifactId>
    <version>${RELEASE_VERSION}</version>
    <packaging>jar</packaging>
    <distributionManagement>
        <repository>
            <id>test-registry</id>
            <url>${MAVEN_REPO_URL}</url>
        </repository>
        <snapshotRepository>
            <id>test-registry</id>
            <url>${MAVEN_REPO_URL}</url>
        </snapshotRepository>
    </distributionManagement>
    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
EOF

cat > src/main/java/com/test/TestClass.java << 'JAVA'
package com.test;
public class TestClass {
    public static String hello() {
        return "Hello from S3 Maven test!";
    }
}
JAVA

# Configure Maven settings
mkdir -p ~/.m2
cat > ~/.m2/settings.xml << EOF
<settings>
  <servers>
    <server>
      <id>test-registry</id>
      <username>${REGISTRY_USER}</username>
      <password>${REGISTRY_PASS}</password>
    </server>
  </servers>
</settings>
EOF

# Build
echo "  Building project..."
mvn clean package -q 2>&1 || { fail "Maven build failed"; exit 1; }

# Deploy release
echo "  Deploying release ${RELEASE_VERSION}..."
if mvn deploy -q -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1; then
    pass "Release deploy succeeded (version $RELEASE_VERSION)"
else
    fail "Release deploy FAILED (version $RELEASE_VERSION)"
    echo ""
    echo "  Retrying with verbose output..."
    mvn deploy -X -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1 | tail -100
fi

# Verify release artifact via GET
echo "  Verifying release artifact via HTTP GET..."
DL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "${MAVEN_REPO_URL}/com/test/s3/s3-test-artifact/${RELEASE_VERSION}/s3-test-artifact-${RELEASE_VERSION}.jar")
if [ "$DL_CODE" = "200" ]; then
    pass "Release artifact downloadable (HTTP $DL_CODE)"
else
    fail "Release artifact NOT downloadable (HTTP $DL_CODE)"
fi

# ---------------------------------------------------------------------------
# Step 3: Test SNAPSHOT artifact deploy (the core of issue #361)
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 3: Testing SNAPSHOT artifact deploy..."

SNAPSHOT_VERSION="2.0.${RUN_ID}-SNAPSHOT"

# Update pom.xml for snapshot
cd "$WORK_DIR"
cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test.s3</groupId>
    <artifactId>s3-test-artifact</artifactId>
    <version>${SNAPSHOT_VERSION}</version>
    <packaging>jar</packaging>
    <distributionManagement>
        <repository>
            <id>test-registry</id>
            <url>${MAVEN_REPO_URL}</url>
        </repository>
        <snapshotRepository>
            <id>test-registry</id>
            <url>${MAVEN_REPO_URL}</url>
        </snapshotRepository>
    </distributionManagement>
    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
EOF

# Build
echo "  Building SNAPSHOT..."
mvn clean package -q 2>&1 || { fail "Maven SNAPSHOT build failed"; exit 1; }

# Deploy snapshot
echo "  Deploying SNAPSHOT ${SNAPSHOT_VERSION}..."
if mvn deploy -q -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1; then
    pass "SNAPSHOT deploy succeeded (version $SNAPSHOT_VERSION)"
else
    fail "SNAPSHOT deploy FAILED (version $SNAPSHOT_VERSION)"
    echo ""
    echo "  Retrying with verbose output..."
    mvn deploy -X -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1 | tail -150
fi

# Verify SNAPSHOT metadata
echo "  Checking maven-metadata.xml..."
META_DIR="com/test/s3/s3-test-artifact/${SNAPSHOT_VERSION}"
META_CODE=$(curl -s -o /tmp/snapshot-metadata.xml -w "%{http_code}" \
    "${MAVEN_REPO_URL}/${META_DIR}/maven-metadata.xml")
if [ "$META_CODE" = "200" ]; then
    pass "SNAPSHOT maven-metadata.xml exists (HTTP $META_CODE)"
    echo "  Metadata content:"
    cat /tmp/snapshot-metadata.xml | head -20
else
    fail "SNAPSHOT maven-metadata.xml missing (HTTP $META_CODE)"
fi

# ---------------------------------------------------------------------------
# Step 4: Test SNAPSHOT re-deploy (overwrite)
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 4: Testing SNAPSHOT re-deploy..."

# Modify source to change the JAR content
cat > src/main/java/com/test/TestClass.java << 'JAVA'
package com.test;
public class TestClass {
    public static String hello() {
        return "Hello from S3 Maven test - UPDATED for re-deploy!";
    }
}
JAVA

echo "  Rebuilding with modified source..."
mvn clean package -q 2>&1 || { fail "Maven SNAPSHOT rebuild failed"; exit 1; }

echo "  Re-deploying SNAPSHOT..."
if mvn deploy -q -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1; then
    pass "SNAPSHOT re-deploy succeeded"
else
    fail "SNAPSHOT re-deploy FAILED"
    echo ""
    echo "  Verbose output:"
    mvn deploy -X -DaltDeploymentRepository="test-registry::default::${MAVEN_REPO_URL}" 2>&1 | tail -100
fi

# ---------------------------------------------------------------------------
# Step 5: Test direct PUT/GET of various file types via curl
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 5: Testing direct PUT/GET via curl..."

# PUT a raw JAR
echo "test jar content" > /tmp/test.jar
PUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    --data-binary @/tmp/test.jar \
    "${MAVEN_REPO_URL}/com/test/s3/curl-test/1.0/curl-test-1.0.jar")
if [ "$PUT_CODE" = "201" ]; then
    pass "Direct PUT JAR succeeded (HTTP $PUT_CODE)"
else
    fail "Direct PUT JAR failed (HTTP $PUT_CODE)"
fi

# PUT a POM
cat > /tmp/test.pom << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.test.s3</groupId>
    <artifactId>curl-test</artifactId>
    <version>1.0</version>
</project>
XML
PUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    --data-binary @/tmp/test.pom \
    "${MAVEN_REPO_URL}/com/test/s3/curl-test/1.0/curl-test-1.0.pom")
if [ "$PUT_CODE" = "201" ]; then
    pass "Direct PUT POM succeeded (HTTP $PUT_CODE)"
else
    fail "Direct PUT POM failed (HTTP $PUT_CODE)"
fi

# PUT a checksum
echo -n "abc123" | curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    --data-binary @- \
    "${MAVEN_REPO_URL}/com/test/s3/curl-test/1.0/curl-test-1.0.jar.sha1" > /tmp/sha_code
SHA_CODE=$(cat /tmp/sha_code)
if [ "$SHA_CODE" = "201" ]; then
    pass "Direct PUT SHA1 checksum succeeded (HTTP $SHA_CODE)"
else
    fail "Direct PUT SHA1 checksum failed (HTTP $SHA_CODE)"
fi

# PUT maven-metadata.xml
cat > /tmp/metadata.xml << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.test.s3</groupId>
  <artifactId>curl-test</artifactId>
  <versioning>
    <latest>1.0</latest>
    <release>1.0</release>
    <versions>
      <version>1.0</version>
    </versions>
    <lastUpdated>20260322120000</lastUpdated>
  </versioning>
</metadata>
XML
META_PUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    --data-binary @/tmp/metadata.xml \
    "${MAVEN_REPO_URL}/com/test/s3/curl-test/maven-metadata.xml")
if [ "$META_PUT_CODE" = "201" ]; then
    pass "Direct PUT maven-metadata.xml succeeded (HTTP $META_PUT_CODE)"
else
    fail "Direct PUT maven-metadata.xml failed (HTTP $META_PUT_CODE)"
fi

# GET back the JAR
GET_CODE=$(curl -s -o /tmp/downloaded.jar -w "%{http_code}" \
    "${MAVEN_REPO_URL}/com/test/s3/curl-test/1.0/curl-test-1.0.jar")
if [ "$GET_CODE" = "200" ]; then
    CONTENT=$(cat /tmp/downloaded.jar)
    if [ "$CONTENT" = "test jar content" ]; then
        pass "GET JAR content matches (HTTP $GET_CODE)"
    else
        fail "GET JAR content mismatch (HTTP $GET_CODE)"
        echo "  Expected: 'test jar content'"
        echo "  Got: '$CONTENT'"
    fi
else
    fail "GET JAR failed (HTTP $GET_CODE)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "Test Results: ${PASSED} passed, ${FAILED} failed"
echo "=============================================="

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "Check backend logs with:"
    echo "  docker compose -f docker-compose.s3-maven-test.yml logs backend"
    exit 1
fi

exit 0
