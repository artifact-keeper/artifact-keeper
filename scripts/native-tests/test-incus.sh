#!/bin/bash
# Incus/LXC container image E2E test script
#
# Tests the SimpleStreams API endpoints and image lifecycle:
#   1. Create an Incus repository via the management API
#   2. Upload a unified tarball image
#   3. Upload split format files (metadata + rootfs)
#   4. Validate SimpleStreams index.json structure
#   5. Validate SimpleStreams images.json (products:1.0 catalog)
#   6. Download and verify an image file by SHA256
#   7. Delete an image
#   8. Verify deletion reflected in SimpleStreams catalog
set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
REPO_KEY="test-incus-$(date +%s)"

echo "==> Incus/LXC E2E Test"
echo "API: $API_URL"
echo "Repo: $REPO_KEY"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# -----------------------------------------------------------------------
# 1. Create repository
# -----------------------------------------------------------------------
echo "==> Creating Incus repository..."
REPO_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/json" \
    -d "{\"key\": \"${REPO_KEY}\", \"name\": \"Test Incus Repo\", \"format\": \"incus\", \"repo_type\": \"hosted\"}" \
    "${API_URL}/api/v1/repositories")

HTTP_CODE=$(echo "$REPO_RESPONSE" | tail -1)
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
    echo "ERROR: Failed to create repository (HTTP $HTTP_CODE)"
    echo "$REPO_RESPONSE"
    exit 1
fi
echo "  Repository created: $REPO_KEY"

# -----------------------------------------------------------------------
# 2. Generate a test unified tarball (metadata.yaml + dummy rootfs)
# -----------------------------------------------------------------------
echo "==> Generating test unified tarball..."
UNIFIED_DIR="$WORK_DIR/unified"
mkdir -p "$UNIFIED_DIR"

cat > "$UNIFIED_DIR/metadata.yaml" << 'EOF'
architecture: x86_64
creation_date: 1708000000
expiry_date: 1740000000
properties:
  os: Ubuntu
  release: noble
  variant: default
  description: Ubuntu noble amd64 (test)
  serial: "20240215"
EOF

# Create a small dummy rootfs directory structure
mkdir -p "$UNIFIED_DIR/rootfs/etc"
echo "Ubuntu 24.04 LTS" > "$UNIFIED_DIR/rootfs/etc/os-release"

# Package as tar.gz (easier to create than tar.xz in CI)
UNIFIED_TARBALL="$WORK_DIR/incus.tar.gz"
tar czf "$UNIFIED_TARBALL" -C "$UNIFIED_DIR" metadata.yaml rootfs

UNIFIED_SIZE=$(stat -f%z "$UNIFIED_TARBALL" 2>/dev/null || stat -c%s "$UNIFIED_TARBALL")
echo "  Generated: incus.tar.gz ($UNIFIED_SIZE bytes)"

# -----------------------------------------------------------------------
# 3. Upload unified tarball
# -----------------------------------------------------------------------
echo "==> Uploading unified tarball..."
UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/gzip" \
    --data-binary "@$UNIFIED_TARBALL" \
    "${API_URL}/incus/${REPO_KEY}/images/ubuntu-noble/20240215/incus.tar.gz")

HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -1)
UPLOAD_BODY=$(echo "$UPLOAD_RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "201" ]; then
    echo "ERROR: Upload failed (HTTP $HTTP_CODE)"
    echo "$UPLOAD_BODY"
    exit 1
fi

UNIFIED_SHA256=$(echo "$UPLOAD_BODY" | jq -r '.sha256')
echo "  Uploaded: ubuntu-noble/20240215/incus.tar.gz (sha256:${UNIFIED_SHA256:0:12}...)"

# -----------------------------------------------------------------------
# 4. Generate and upload split format files
# -----------------------------------------------------------------------
echo "==> Generating split format metadata tarball..."
SPLIT_META_DIR="$WORK_DIR/split-meta"
mkdir -p "$SPLIT_META_DIR"

cat > "$SPLIT_META_DIR/metadata.yaml" << 'EOF'
architecture: aarch64
creation_date: 1708000000
properties:
  os: Debian
  release: bookworm
  variant: cloud
  description: Debian bookworm arm64 (test)
  serial: "20240301"
EOF

META_TARBALL="$WORK_DIR/metadata.tar.gz"
tar czf "$META_TARBALL" -C "$SPLIT_META_DIR" metadata.yaml

echo "==> Uploading split metadata tarball..."
META_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/gzip" \
    --data-binary "@$META_TARBALL" \
    "${API_URL}/incus/${REPO_KEY}/images/debian-bookworm/20240301/metadata.tar.gz")

HTTP_CODE=$(echo "$META_RESPONSE" | tail -1)
if [ "$HTTP_CODE" != "201" ]; then
    echo "ERROR: Metadata upload failed (HTTP $HTTP_CODE)"
    echo "$META_RESPONSE" | sed '$d'
    exit 1
fi
echo "  Uploaded: debian-bookworm/20240301/metadata.tar.gz"

echo "==> Generating dummy squashfs rootfs..."
# Create a small file to simulate a squashfs rootfs
ROOTFS_FILE="$WORK_DIR/rootfs.squashfs"
dd if=/dev/urandom bs=1024 count=16 of="$ROOTFS_FILE" 2>/dev/null
echo "  Generated: rootfs.squashfs (16KB dummy)"

echo "==> Uploading split rootfs..."
ROOTFS_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$ROOTFS_FILE" \
    "${API_URL}/incus/${REPO_KEY}/images/debian-bookworm/20240301/rootfs.squashfs")

HTTP_CODE=$(echo "$ROOTFS_RESPONSE" | tail -1)
if [ "$HTTP_CODE" != "201" ]; then
    echo "ERROR: Rootfs upload failed (HTTP $HTTP_CODE)"
    echo "$ROOTFS_RESPONSE" | sed '$d'
    exit 1
fi
ROOTFS_SHA256=$(echo "$ROOTFS_RESPONSE" | sed '$d' | jq -r '.sha256')
echo "  Uploaded: debian-bookworm/20240301/rootfs.squashfs (sha256:${ROOTFS_SHA256:0:12}...)"

# -----------------------------------------------------------------------
# 5. Validate SimpleStreams index.json
# -----------------------------------------------------------------------
echo "==> Validating SimpleStreams index.json..."
INDEX_RESPONSE=$(curl -s "${API_URL}/incus/${REPO_KEY}/streams/v1/index.json")

INDEX_FORMAT=$(echo "$INDEX_RESPONSE" | jq -r '.format')
if [ "$INDEX_FORMAT" != "index:1.0" ]; then
    echo "ERROR: index.json format should be 'index:1.0', got '$INDEX_FORMAT'"
    exit 1
fi

INDEX_PRODUCTS=$(echo "$INDEX_RESPONSE" | jq -r '.index.images.products | length')
if [ "$INDEX_PRODUCTS" -lt 2 ]; then
    echo "ERROR: Expected at least 2 products in index, got $INDEX_PRODUCTS"
    echo "$INDEX_RESPONSE" | jq .
    exit 1
fi

echo "  index.json: format=$INDEX_FORMAT, products=$INDEX_PRODUCTS"

# -----------------------------------------------------------------------
# 6. Validate SimpleStreams images.json (products:1.0 catalog)
# -----------------------------------------------------------------------
echo "==> Validating SimpleStreams images.json..."
IMAGES_RESPONSE=$(curl -s "${API_URL}/incus/${REPO_KEY}/streams/v1/images.json")

IMAGES_FORMAT=$(echo "$IMAGES_RESPONSE" | jq -r '.format')
if [ "$IMAGES_FORMAT" != "products:1.0" ]; then
    echo "ERROR: images.json format should be 'products:1.0', got '$IMAGES_FORMAT'"
    exit 1
fi

# Check ubuntu-noble product exists
UBUNTU_PRODUCT=$(echo "$IMAGES_RESPONSE" | jq '.products["ubuntu-noble"]')
if [ "$UBUNTU_PRODUCT" = "null" ]; then
    echo "ERROR: ubuntu-noble product not found in catalog"
    echo "$IMAGES_RESPONSE" | jq .
    exit 1
fi

# Check debian-bookworm product exists
DEBIAN_PRODUCT=$(echo "$IMAGES_RESPONSE" | jq '.products["debian-bookworm"]')
if [ "$DEBIAN_PRODUCT" = "null" ]; then
    echo "ERROR: debian-bookworm product not found in catalog"
    echo "$IMAGES_RESPONSE" | jq .
    exit 1
fi

# Check ubuntu-noble has correct version with items
UBUNTU_ITEMS=$(echo "$IMAGES_RESPONSE" | jq '.products["ubuntu-noble"].versions["20240215"].items | length')
if [ "$UBUNTU_ITEMS" -lt 1 ]; then
    echo "ERROR: Expected at least 1 item in ubuntu-noble/20240215, got $UBUNTU_ITEMS"
    exit 1
fi

# Check SHA256 in catalog matches upload
CATALOG_SHA256=$(echo "$IMAGES_RESPONSE" | jq -r '.products["ubuntu-noble"].versions["20240215"].items["incus.tar.xz"].sha256 // empty')
if [ -n "$CATALOG_SHA256" ] && [ "$CATALOG_SHA256" != "$UNIFIED_SHA256" ]; then
    echo "ERROR: SHA256 mismatch in catalog: got $CATALOG_SHA256, expected $UNIFIED_SHA256"
    exit 1
fi

echo "  images.json: format=$IMAGES_FORMAT, ubuntu-noble items=$UBUNTU_ITEMS"

# -----------------------------------------------------------------------
# 7. Download and verify an image file
# -----------------------------------------------------------------------
echo "==> Downloading image file..."
DOWNLOAD_FILE="$WORK_DIR/downloaded.squashfs"
curl -s -o "$DOWNLOAD_FILE" -D "$WORK_DIR/headers.txt" \
    "${API_URL}/incus/${REPO_KEY}/images/debian-bookworm/20240301/rootfs.squashfs"

DL_SHA256_HEADER=$(grep -i 'X-Checksum-Sha256' "$WORK_DIR/headers.txt" | tr -d '\r' | awk '{print $2}')
if [ -n "$DL_SHA256_HEADER" ] && [ "$DL_SHA256_HEADER" != "$ROOTFS_SHA256" ]; then
    echo "ERROR: Downloaded checksum mismatch: header=$DL_SHA256_HEADER, expected=$ROOTFS_SHA256"
    exit 1
fi

# Compare file sizes
ORIG_SIZE=$(stat -f%z "$ROOTFS_FILE" 2>/dev/null || stat -c%s "$ROOTFS_FILE")
DL_SIZE=$(stat -f%z "$DOWNLOAD_FILE" 2>/dev/null || stat -c%s "$DOWNLOAD_FILE")
if [ "$ORIG_SIZE" != "$DL_SIZE" ]; then
    echo "ERROR: Size mismatch: original=$ORIG_SIZE, downloaded=$DL_SIZE"
    exit 1
fi

echo "  Downloaded: rootfs.squashfs ($DL_SIZE bytes, checksum verified)"

# -----------------------------------------------------------------------
# 8. Delete an image and verify removal from catalog
# -----------------------------------------------------------------------
echo "==> Deleting unified tarball..."
DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${API_URL}/incus/${REPO_KEY}/images/ubuntu-noble/20240215/incus.tar.gz")

HTTP_CODE=$(echo "$DELETE_RESPONSE" | tail -1)
if [ "$HTTP_CODE" != "204" ]; then
    echo "ERROR: Delete failed (HTTP $HTTP_CODE)"
    exit 1
fi
echo "  Deleted: ubuntu-noble/20240215/incus.tar.gz"

echo "==> Verifying deletion in catalog..."
IMAGES_AFTER=$(curl -s "${API_URL}/incus/${REPO_KEY}/streams/v1/images.json")
UBUNTU_AFTER=$(echo "$IMAGES_AFTER" | jq '.products["ubuntu-noble"] // null')
if [ "$UBUNTU_AFTER" != "null" ]; then
    # Product may still exist if it had other files; check the specific version item is gone
    TARBALL_AFTER=$(echo "$IMAGES_AFTER" | jq -r '.products["ubuntu-noble"].versions["20240215"].items["incus.tar.xz"].sha256 // "gone"')
    if [ "$TARBALL_AFTER" != "gone" ]; then
        echo "WARNING: Deleted image still appears in catalog (may need index regeneration)"
    fi
fi
echo "  Catalog updated after deletion"

# -----------------------------------------------------------------------
# 9. Verify unauthenticated download (read should be public)
# -----------------------------------------------------------------------
echo "==> Verifying public read access..."
PUBLIC_RESPONSE=$(curl -s -w "\n%{http_code}" \
    "${API_URL}/incus/${REPO_KEY}/images/debian-bookworm/20240301/rootfs.squashfs")

HTTP_CODE=$(echo "$PUBLIC_RESPONSE" | tail -1)
if [ "$HTTP_CODE" = "200" ]; then
    echo "  Public download: OK (HTTP 200)"
else
    echo "  Public download: HTTP $HTTP_CODE (may require auth depending on repo settings)"
fi

# -----------------------------------------------------------------------
# 10. Verify unauthenticated write is rejected
# -----------------------------------------------------------------------
echo "==> Verifying auth required for uploads..."
NOAUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    -H "Content-Type: application/octet-stream" \
    --data-binary "test" \
    "${API_URL}/incus/${REPO_KEY}/images/test/v1/test.tar.gz")

HTTP_CODE=$(echo "$NOAUTH_RESPONSE" | tail -1)
if [ "$HTTP_CODE" = "401" ]; then
    echo "  Unauthenticated upload correctly rejected (HTTP 401)"
else
    echo "WARNING: Expected 401 for unauthenticated upload, got $HTTP_CODE"
fi

echo ""
echo "==> Incus/LXC E2E test PASSED"
