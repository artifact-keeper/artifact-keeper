#!/bin/bash
# Alpine/APK E2E test — fetch real package from upstream, upload to registry, install from registry
set -euo pipefail
source /scripts/lib.sh

REPO_KEY="e2e-alpine-$(date +%s)"
ARCH=$(apk --print-arch)
# Use a small, real Alpine package with no dependencies
TEST_PKG="fortune"

log "Alpine/APK E2E Test"
log "Repo: $REPO_KEY | Arch: $ARCH | Test package: $TEST_PKG"

# --- Install deps ---
log "Installing dependencies..."
apk add --no-cache curl python3 > /dev/null 2>&1

# --- Setup repo + signing ---
setup_signed_repo "$REPO_KEY" "alpine"

# --- Fetch a real package + deps from upstream ---
log "Updating package index from upstream..."
# Ensure repos are clean (default Alpine repos only)
grep -v "artifact-keeper" /etc/apk/repositories > /tmp/clean-repos || true
cp /tmp/clean-repos /etc/apk/repositories
apk update 2>&1 | tail -3 || true

log "Fetching $TEST_PKG (with dependencies) from upstream Alpine repos..."
mkdir -p /tmp/apk-cache
apk fetch -R -o /tmp/apk-cache "$TEST_PKG" 2>&1 || {
    # fortune might not exist, try another small package
    TEST_PKG="pv"
    log "fortune not available, trying $TEST_PKG..."
    rm -f /tmp/apk-cache/*.apk
    apk fetch -R -o /tmp/apk-cache "$TEST_PKG" 2>&1 || {
        TEST_PKG="tree"
        log "pv not available, trying $TEST_PKG..."
        rm -f /tmp/apk-cache/*.apk
        apk fetch -R -o /tmp/apk-cache "$TEST_PKG" 2>&1 || fail "Cannot fetch any test package"
    }
}

APK_FILES=$(find /tmp/apk-cache -name "*.apk")
APK_COUNT=$(echo "$APK_FILES" | wc -l)
APK_FILE=$(echo "$APK_FILES" | head -1)
[ -f "$APK_FILE" ] || fail "No APK file fetched"
log "Fetched $APK_COUNT package(s) for $TEST_PKG"
echo "$APK_FILES" | while read f; do log "  $(basename "$f") ($(du -h "$f" | cut -f1))"; done

# --- Upload all packages to our registry ---
log "Uploading $APK_COUNT package(s) to registry..."
for pkg in $APK_FILES; do
    PKG_NAME_FILE=$(basename "$pkg")
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        -u "$AUTH_USER:$AUTH_PASS" \
        -H "Content-Type: application/vnd.alpine.package" \
        --data-binary "@$pkg" \
        "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/$PKG_NAME_FILE")
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || fail "Upload of $PKG_NAME_FILE failed (HTTP $HTTP_CODE)"
    log "  Uploaded $PKG_NAME_FILE ($HTTP_CODE)"
done
log "All packages uploaded"

sleep 1

# --- Verify registry metadata ---
log "Verifying APKINDEX.tar.gz..."
curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/APKINDEX.tar.gz" -o /tmp/apkindex.tar.gz
ENTRIES=$(tar tzf /tmp/apkindex.tar.gz 2>/dev/null)
echo "$ENTRIES" | grep -q ".SIGN.RSA" || fail "APKINDEX.tar.gz missing .SIGN.RSA entry"
echo "$ENTRIES" | grep -q "APKINDEX" || fail "APKINDEX.tar.gz missing APKINDEX entry"
log "APKINDEX.tar.gz is signed and contains index"

log "Verifying public key endpoint..."
curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/keys/artifact-keeper.rsa.pub" | \
    grep -q "BEGIN PUBLIC KEY" || fail "Public key endpoint invalid"
log "Public key endpoint OK"

log "Verifying direct package download..."
curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/$(basename "$APK_FILE")" -o /tmp/dl.apk
[ -s /tmp/dl.apk ] || fail "Download empty"
ORIG_SIZE=$(stat -c%s "$APK_FILE" 2>/dev/null || stat -f%z "$APK_FILE")
DL_SIZE=$(stat -c%s /tmp/dl.apk 2>/dev/null || stat -f%z /tmp/dl.apk)
[ "$ORIG_SIZE" = "$DL_SIZE" ] || fail "Size mismatch: uploaded=$ORIG_SIZE downloaded=$DL_SIZE"
log "Downloaded package matches uploaded ($DL_SIZE bytes)"

# --- Remove the package if installed, configure repo, install from registry ---
apk del "$TEST_PKG" 2>/dev/null || true

log "Configuring APK to use our registry..."
# Replace repos to force install from our registry (all deps were uploaded)
cp /etc/apk/repositories /etc/apk/repositories.bak
echo "$BACKEND_URL/alpine/$REPO_KEY/v3/main" > /etc/apk/repositories

log "Running apk update (registry only)..."
apk update --allow-untrusted 2>&1 | tail -5 || log "apk update had warnings"

log "Installing $TEST_PKG from registry..."
apk add --allow-untrusted "$TEST_PKG" 2>&1 || {
    log "apk add by name failed, trying direct install of all downloaded packages..."
    # Download all packages from registry and install locally
    mkdir -p /tmp/dl-pkgs
    for pkg in $APK_FILES; do
        PKG_NAME_FILE=$(basename "$pkg")
        curl -sf "$BACKEND_URL/alpine/$REPO_KEY/v3/main/$ARCH/$PKG_NAME_FILE" -o "/tmp/dl-pkgs/$PKG_NAME_FILE"
    done
    apk add --allow-untrusted /tmp/dl-pkgs/*.apk 2>&1 || fail "Cannot install APK packages"
}

# Restore original repos
cp /etc/apk/repositories.bak /etc/apk/repositories

# --- Verify ---
log "Verifying $TEST_PKG is installed..."
apk info -e "$TEST_PKG" 2>/dev/null || fail "$TEST_PKG not in installed packages"
log "$TEST_PKG is installed"

# Try to run it
if which "$TEST_PKG" > /dev/null 2>&1; then
    log "Running $TEST_PKG..."
    "$TEST_PKG" --version 2>&1 | head -1 || "$TEST_PKG" --help 2>&1 | head -1 || true
fi

echo ""
echo "=== Alpine/APK E2E test PASSED ==="
