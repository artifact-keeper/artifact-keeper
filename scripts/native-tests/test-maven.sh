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

echo ""
echo "Maven native client test PASSED"
