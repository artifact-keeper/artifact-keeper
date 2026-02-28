#!/bin/bash
# Maven native client test script
# Tests push (mvn deploy) and pull (mvn dependency:get) operations
# against the Maven 2 repository layout at /maven/{repo_key}/
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080/maven/test-maven}"
REGISTRY_USER="${REGISTRY_USER:-admin}"
REGISTRY_PASS="${REGISTRY_PASS:-admin123}"
CA_CERT="${CA_CERT:-}"
TEST_VERSION="1.0.$(date +%s)"

echo "==> Maven Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Version: $TEST_VERSION"

# Generate test project
echo "==> Generating test project..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p src/main/java/com/test

cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.test</groupId>
    <artifactId>test-artifact-native</artifactId>
    <version>$TEST_VERSION</version>
    <packaging>jar</packaging>

    <distributionManagement>
        <repository>
            <id>test-registry</id>
            <url>$REGISTRY_URL</url>
        </repository>
    </distributionManagement>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
EOF

cat > src/main/java/com/test/TestClass.java << EOF
package com.test;

public class TestClass {
    public static String hello() {
        return "Hello from test-artifact-native!";
    }
}
EOF

# Configure Maven settings
echo "==> Configuring Maven settings..."
mkdir -p ~/.m2
cat > ~/.m2/settings.xml << EOF
<settings>
  <servers>
    <server>
      <id>test-registry</id>
      <username>$REGISTRY_USER</username>
      <password>$REGISTRY_PASS</password>
    </server>
  </servers>
</settings>
EOF

# Build and deploy
echo "==> Building and deploying artifact..."
mvn clean package -q
mvn deploy -q -DaltDeploymentRepository=test-registry::default::$REGISTRY_URL

# Verify push via curl
echo "==> Verifying artifact was deployed..."
sleep 2

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$REGISTRY_URL/com/test/test-artifact-native/$TEST_VERSION/test-artifact-native-$TEST_VERSION.jar")

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200 for artifact download, got $HTTP_CODE"
  exit 1
fi

echo "==> Artifact download returned HTTP $HTTP_CODE"

# Verify maven-metadata.xml
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$REGISTRY_URL/com/test/test-artifact-native/maven-metadata.xml")

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200 for maven-metadata.xml, got $HTTP_CODE"
  exit 1
fi

echo "==> maven-metadata.xml returned HTTP $HTTP_CODE"

# Verify checksum
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$REGISTRY_URL/com/test/test-artifact-native/$TEST_VERSION/test-artifact-native-$TEST_VERSION.jar.sha1")

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200 for .sha1 checksum, got $HTTP_CODE"
  exit 1
fi

echo "==> SHA1 checksum returned HTTP $HTTP_CODE"

# Pull with mvn dependency:get
echo "==> Fetching artifact with Maven..."
mkdir -p "$WORK_DIR/test-consumer"
cd "$WORK_DIR/test-consumer"

cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.test</groupId>
    <artifactId>test-consumer</artifactId>
    <version>1.0.0</version>

    <repositories>
        <repository>
            <id>test-registry</id>
            <url>$REGISTRY_URL</url>
        </repository>
    </repositories>

    <dependencies>
        <dependency>
            <groupId>com.test</groupId>
            <artifactId>test-artifact-native</artifactId>
            <version>$TEST_VERSION</version>
        </dependency>
    </dependencies>
</project>
EOF

mvn dependency:resolve -q

echo "==> Release artifact test PASSED"

# -------------------------------------------------------------------------
# SNAPSHOT re-upload test
# -------------------------------------------------------------------------
echo ""
echo "==> Testing SNAPSHOT re-upload..."
SNAP_VERSION="1.0.0-SNAPSHOT"

cd "$WORK_DIR"
rm -rf snapshot-project
mkdir -p snapshot-project/src/main/java/com/test
cd snapshot-project

cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.test</groupId>
    <artifactId>snapshot-test</artifactId>
    <version>$SNAP_VERSION</version>
    <packaging>jar</packaging>

    <distributionManagement>
        <snapshotRepository>
            <id>test-registry</id>
            <url>$REGISTRY_URL</url>
        </snapshotRepository>
    </distributionManagement>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
EOF

cat > src/main/java/com/test/SnapshotClass.java << EOF
package com.test;

public class SnapshotClass {
    public static String version() { return "v1"; }
}
EOF

echo "==> First SNAPSHOT deploy..."
mvn clean package -q
mvn deploy -q -DaltDeploymentRepository=test-registry::default::$REGISTRY_URL

sleep 1

# Verify first upload
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$REGISTRY_URL/com/test/snapshot-test/$SNAP_VERSION/snapshot-test-$SNAP_VERSION.jar")

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200 for first SNAPSHOT upload, got $HTTP_CODE"
  exit 1
fi
echo "==> First SNAPSHOT upload verified (HTTP $HTTP_CODE)"

# Get checksum of first upload
FIRST_SHA=$(curl -s "$REGISTRY_URL/com/test/snapshot-test/$SNAP_VERSION/snapshot-test-$SNAP_VERSION.jar.sha1")

# Modify source and re-deploy
echo "==> Modifying source and re-deploying SNAPSHOT..."
cat > src/main/java/com/test/SnapshotClass.java << EOF
package com.test;

public class SnapshotClass {
    public static String version() { return "v2-updated"; }
}
EOF

mvn clean package -q
mvn deploy -q -DaltDeploymentRepository=test-registry::default::$REGISTRY_URL

sleep 1

# Verify re-upload succeeded (not 409 Conflict or 500)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$REGISTRY_URL/com/test/snapshot-test/$SNAP_VERSION/snapshot-test-$SNAP_VERSION.jar")

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected HTTP 200 after SNAPSHOT re-upload, got $HTTP_CODE"
  exit 1
fi

# Verify content actually changed
SECOND_SHA=$(curl -s "$REGISTRY_URL/com/test/snapshot-test/$SNAP_VERSION/snapshot-test-$SNAP_VERSION.jar.sha1")

if [ "$FIRST_SHA" = "$SECOND_SHA" ]; then
  echo "FAIL: SNAPSHOT content did not change after re-upload (same SHA1)"
  exit 1
fi

echo "==> SNAPSHOT re-upload verified: content updated (SHA1 changed)"

# Verify release artifact re-upload is still rejected
echo "==> Verifying release re-upload is rejected..."
cd "$WORK_DIR"
cd snapshot-project

cat > pom.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.test</groupId>
    <artifactId>test-artifact-native</artifactId>
    <version>$TEST_VERSION</version>
    <packaging>jar</packaging>

    <distributionManagement>
        <repository>
            <id>test-registry</id>
            <url>$REGISTRY_URL</url>
        </repository>
    </distributionManagement>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
EOF

mvn clean package -q
if mvn deploy -q -DaltDeploymentRepository=test-registry::default::$REGISTRY_URL 2>/dev/null; then
  echo "FAIL: Release re-upload should have been rejected (409 Conflict)"
  exit 1
fi

echo "==> Release re-upload correctly rejected (409 Conflict)"

echo ""
echo "Maven native client test PASSED (release + SNAPSHOT)"
