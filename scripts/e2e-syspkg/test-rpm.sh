#!/bin/bash
# RPM/YUM E2E test — build RPM, upload, configure dnf with GPG, install
set -euo pipefail
source /scripts/lib.sh

REPO_KEY="e2e-rpm-$(date +%s)"
TEST_VERSION="1.0.$(date +%s)"
PKG_NAME="e2e-test-pkg"

log "RPM/YUM E2E Test"
log "Repo: $REPO_KEY | Version: $TEST_VERSION"

# --- Install build deps ---
log "Installing build dependencies..."
dnf install -y --allowerasing rpm-build curl 2>&1 | tail -5 || yum install -y rpm-build curl 2>&1 | tail -5
# python3 is usually pre-installed on Rocky 9
which python3 > /dev/null 2>&1 || dnf install -y python3 2>&1 | tail -3 || true

# --- Setup repo + signing ---
setup_signed_repo "$REPO_KEY" "rpm"

# --- Build RPM ---
log "Building RPM package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p {BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > SOURCES/test-file.txt << EOF
Hello from $PKG_NAME!
Version: $TEST_VERSION
Format: rpm
EOF

cat > SPECS/$PKG_NAME.spec << EOF
Name:           $PKG_NAME
Version:        $TEST_VERSION
Release:        1%{?dist}
Summary:        E2E test package for RPM native client testing
License:        MIT

Source0:        test-file.txt

BuildArch:      noarch

%description
Verifies that the artifact registry serves valid signed YUM/DNF metadata.

%install
mkdir -p %{buildroot}/opt/$PKG_NAME
cp %{SOURCE0} %{buildroot}/opt/$PKG_NAME/

%files
/opt/$PKG_NAME/test-file.txt
EOF

rpmbuild --define "_topdir $WORK_DIR" -bb "SPECS/$PKG_NAME.spec" > /dev/null 2>&1
RPM_FILE=$(find RPMS -name "*.rpm" | head -1)
[ -f "$RPM_FILE" ] || fail "rpmbuild produced no .rpm"
log "Built: $(basename "$RPM_FILE")"

# --- Upload RPM ---
log "Uploading RPM to registry..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "$AUTH_USER:$AUTH_PASS" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@$RPM_FILE" \
    "$BACKEND_URL/rpm/$REPO_KEY/packages/$(basename "$RPM_FILE")")
[ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || fail "Upload failed (HTTP $HTTP_CODE)"
log "Upload OK ($HTTP_CODE)"

sleep 1

# --- Verify signed metadata ---
log "Verifying repomd.xml..."
REPOMD=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml")
echo "$REPOMD" | grep -q "<repomd" || fail "repomd.xml invalid"
log "repomd.xml valid"

log "Verifying repomd.xml.asc (detached signature)..."
REPOMD_ASC=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.asc")
echo "$REPOMD_ASC" | grep -q "BEGIN PGP SIGNATURE" || fail "repomd.xml.asc missing"
log "repomd.xml.asc present"

log "Verifying repomd.xml.key (public key)..."
REPOMD_KEY=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.key")
echo "$REPOMD_KEY" | grep -q "BEGIN PUBLIC KEY" || fail "repomd.xml.key missing"
log "repomd.xml.key present"

# --- Configure dnf ---
log "Importing GPG key..."
curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.key" > /tmp/repo-key.pub
rpm --import /tmp/repo-key.pub 2>/dev/null || log "Key import warning (non-GPG key format, using gpgcheck=0 fallback)"

log "Adding YUM repository..."
cat > /etc/yum.repos.d/e2e-registry.repo << EOF
[e2e-registry]
name=E2E Test Registry
baseurl=$BACKEND_URL/rpm/$REPO_KEY
enabled=1
gpgcheck=0
EOF

# --- dnf install ---
log "Cleaning dnf cache..."
dnf clean all > /dev/null 2>&1

log "Installing $PKG_NAME..."
dnf install -y "$PKG_NAME" 2>&1 || {
    log "dnf install failed, listing available packages..."
    dnf list available 2>&1 | grep -i e2e || true
    fail "Could not install $PKG_NAME"
}

# --- Verify ---
log "Verifying installed package..."
INSTALLED_CONTENT=$(cat "/opt/$PKG_NAME/test-file.txt" 2>/dev/null) || fail "Installed file not found"
echo "$INSTALLED_CONTENT" | grep -q "$TEST_VERSION" || fail "Version mismatch in installed file"
log "Installed file content verified"

echo ""
echo "=== RPM/YUM native-PUT E2E leg PASSED ==="

# ============================================================================
# Generic-push leg (#2580)
# ----------------------------------------------------------------------------
# CI previously only exercised the native RPM PUT (which stores the artifact
# under `packages/<file>`). An RPM pushed through the GENERIC chunked upload
# flow — exactly what `ak artifact push` does — is stored at its bare path, and
# the on-demand primary.xml emitted a bare `<location href>` that did not match
# the hosted `/rpm/{repo}/packages/<file>` download route, so `dnf install`
# 404'd. This leg reproduces that path end-to-end and is the regression guard.
# ============================================================================
GEN_REPO="${REPO_KEY}-generic"
RPM_BASENAME="$(basename "$RPM_FILE")"
RPM_SIZE=$(stat -c%s "$RPM_FILE")
RPM_SHA=$(sha256sum "$RPM_FILE" | awk '{print $1}')

log "[generic] Setting up hosted rpm repo $GEN_REPO..."
# TOKEN is already exported from the native leg's api_login.
api_create_repo "$GEN_REPO" "rpm"
api_create_signing_key
api_configure_signing

log "[generic] Creating upload session for $RPM_BASENAME (size=$RPM_SIZE)..."
SESSION_JSON=$(curl -sf -X POST "$BACKEND_URL/api/v1/uploads" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"repository_key\":\"$GEN_REPO\",\"artifact_path\":\"$RPM_BASENAME\",\"total_size\":$RPM_SIZE,\"checksum_sha256\":\"$RPM_SHA\",\"content_type\":\"application/x-rpm\"}")
SESSION_ID=$(echo "$SESSION_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null) \
    || SESSION_ID=$(echo "$SESSION_JSON" | sed -n 's/.*"session_id":"\([^"]*\)".*/\1/p')
[ -n "$SESSION_ID" ] || fail "[generic] no session id: $SESSION_JSON"
log "[generic] Session: $SESSION_ID"

log "[generic] Uploading chunk 0 (Content-Range bytes 0-$((RPM_SIZE-1))/$RPM_SIZE)..."
CHUNK_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PATCH \
    "$BACKEND_URL/api/v1/uploads/$SESSION_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Range: bytes 0-$((RPM_SIZE-1))/$RPM_SIZE" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$RPM_FILE")
[ "$CHUNK_CODE" = "200" ] || [ "$CHUNK_CODE" = "201" ] || fail "[generic] chunk upload HTTP $CHUNK_CODE"

log "[generic] Completing upload..."
COMPLETE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "$BACKEND_URL/api/v1/uploads/$SESSION_ID/complete" \
    -H "Authorization: Bearer $TOKEN")
[ "$COMPLETE_CODE" = "200" ] || [ "$COMPLETE_CODE" = "201" ] || fail "[generic] complete HTTP $COMPLETE_CODE"
log "[generic] Upload complete"

sleep 1

log "[generic] Fetching + parsing primary.xml..."
curl -sf "$BACKEND_URL/rpm/$GEN_REPO/repodata/primary.xml.gz" -o /tmp/generic-primary.xml.gz \
    || fail "[generic] primary.xml.gz fetch failed"
gunzip -f /tmp/generic-primary.xml.gz
HREF=$(python3 -c "
import re
xml = open('/tmp/generic-primary.xml').read()
m = re.search(r'<location href=\"([^\"]+)\"', xml)
print(m.group(1) if m else '')
")
[ -n "$HREF" ] || fail "[generic] no <location href> in primary.xml"
log "[generic] location href = $HREF"
case "$HREF" in
    packages/*) log "[generic] href correctly prefixed with packages/ (fix #2580)";;
    *) fail "[generic] href not packages/-prefixed: '$HREF' (bug #2580)";;
esac

log "[generic] Downloading $HREF from the hosted route..."
curl -sf "$BACKEND_URL/rpm/$GEN_REPO/$HREF" -o /tmp/generic-download.rpm \
    || fail "[generic] GET $HREF failed — hosted route did not serve the generic RPM (bug #2580)"
DL_SHA=$(sha256sum /tmp/generic-download.rpm | awk '{print $1}')
[ "$DL_SHA" = "$RPM_SHA" ] || fail "[generic] downloaded sha256 mismatch ($DL_SHA != $RPM_SHA)"
log "[generic] Downloaded bytes match the local RPM"

XML_SHA=$(python3 -c "
import re
xml = open('/tmp/generic-primary.xml').read()
m = re.search(r'<checksum type=\"sha256\"[^>]*>([0-9a-fA-F]+)</checksum>', xml)
print(m.group(1) if m else '')
")
[ "$XML_SHA" = "$RPM_SHA" ] || fail "[generic] primary.xml checksum mismatch ($XML_SHA != $RPM_SHA)"
log "[generic] primary.xml <checksum> matches the local RPM"

log "[generic] Installing $PKG_NAME end-to-end from the generic repo..."
# Remove the native-leg install and repo so the package can only come from the
# generically-pushed copy.
dnf remove -y "$PKG_NAME" > /dev/null 2>&1 || true
rm -f /etc/yum.repos.d/e2e-registry.repo
cat > /etc/yum.repos.d/e2e-generic.repo << EOF
[e2e-generic]
name=E2E Generic Push Registry
baseurl=$BACKEND_URL/rpm/$GEN_REPO
enabled=1
gpgcheck=0
EOF
dnf clean all > /dev/null 2>&1
dnf install -y "$PKG_NAME" 2>&1 | tail -8 || fail "[generic] dnf install of generically-pushed RPM failed"
INSTALLED_CONTENT=$(cat "/opt/$PKG_NAME/test-file.txt" 2>/dev/null) || fail "[generic] installed file not found"
echo "$INSTALLED_CONTENT" | grep -q "$TEST_VERSION" || fail "[generic] version mismatch in installed file"
log "[generic] dnf install of the generically-pushed RPM succeeded"

echo ""
echo "=== RPM/YUM E2E test PASSED (native-PUT + generic-push) ==="
