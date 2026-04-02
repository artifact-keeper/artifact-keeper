#!/bin/bash
# Protobuf / BSR native client test script
# Tests push (upload), pull (download), module listing, and label operations
# via the Connect RPC endpoints at /proto/{repo_key}/
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
REPO_KEY="${REPO_KEY:-test-protobuf}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "==> Protobuf / BSR Native Client Test"
echo "Registry: $REGISTRY_URL"
echo "Repo key: $REPO_KEY"

# --------------------------------------------------------------------------
# Auth: get a token
# --------------------------------------------------------------------------
echo "==> Logging in..."
TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "ERROR: Failed to authenticate"
  exit 1
fi
echo "  Authenticated successfully"

# --------------------------------------------------------------------------
# Create test protobuf repo (idempotent)
# --------------------------------------------------------------------------
echo "==> Creating protobuf repository..."
curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO_KEY\",\"name\":\"Test Protobuf\",\"format\":\"protobuf\",\"repo_type\":\"local\",\"is_public\":true}" \
  >/dev/null 2>&1 || true
echo "  Repository ready"

# --------------------------------------------------------------------------
# Helper: base64 encode content
# --------------------------------------------------------------------------
b64() { echo -n "$1" | base64 | tr -d '\n'; }

# --------------------------------------------------------------------------
# Test 1: Upload a module via Connect RPC Upload endpoint
# --------------------------------------------------------------------------
echo "==> Test 1: Upload module (buf push equivalent)..."

PROTO_CONTENT='syntax = "proto3";
package acme.payments.v1;

message PaymentRequest {
  string order_id = 1;
  int64 amount_cents = 2;
  string currency = 3;
}

message PaymentResponse {
  string payment_id = 1;
  string status = 2;
}'

BUF_YAML_CONTENT='version: v2
name: buf.build/acme/payments
deps: []'

UPLOAD_BODY=$(cat <<JSONEOF
{
  "contents": [
    {
      "moduleRef": {
        "owner": "acme",
        "module": "payments"
      },
      "files": [
        {
          "path": "acme/payments/v1/payments.proto",
          "content": "$(b64 "$PROTO_CONTENT")"
        },
        {
          "path": "buf.yaml",
          "content": "$(b64 "$BUF_YAML_CONTENT")"
        }
      ],
      "depRefs": [],
      "labelRefs": [
        {"name": "main"},
        {"name": "v1.0.0"}
      ]
    }
  ]
}
JSONEOF
)

UPLOAD_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1beta1.UploadService/Upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPLOAD_BODY")

COMMIT_ID=$(echo "$UPLOAD_RESP" | jq -r '.commits[0].id')
if [ -z "$COMMIT_ID" ] || [ "$COMMIT_ID" = "null" ]; then
  echo "ERROR: Upload failed"
  echo "$UPLOAD_RESP"
  exit 1
fi
echo "  Uploaded commit: ${COMMIT_ID:0:16}..."

# --------------------------------------------------------------------------
# Test 2: GetModules — verify module exists
# --------------------------------------------------------------------------
echo "==> Test 2: GetModules..."

MODULES_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1.ModuleService/GetModules" \
  -H "Content-Type: application/json" \
  -d '{"moduleRefs": [{"owner": "acme", "module": "payments"}]}')

MODULE_NAME=$(echo "$MODULES_RESP" | jq -r '.modules[0].name')
if [ "$MODULE_NAME" != "payments" ]; then
  echo "ERROR: GetModules returned unexpected name: $MODULE_NAME"
  echo "$MODULES_RESP"
  exit 1
fi
echo "  Module found: acme/$MODULE_NAME"

# --------------------------------------------------------------------------
# Test 3: GetLabels — verify labels were created
# --------------------------------------------------------------------------
echo "==> Test 3: GetLabels..."

LABELS_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1.LabelService/GetLabels" \
  -H "Content-Type: application/json" \
  -d '{"labelRefs": [{"owner": "acme", "module": "payments"}]}')

LABEL_COUNT=$(echo "$LABELS_RESP" | jq '.labels | length')
if [ "$LABEL_COUNT" -lt 2 ]; then
  echo "ERROR: Expected at least 2 labels, got $LABEL_COUNT"
  echo "$LABELS_RESP"
  exit 1
fi
echo "  Found $LABEL_COUNT labels (main, v1.0.0)"

# --------------------------------------------------------------------------
# Test 4: GetCommits — resolve by label
# --------------------------------------------------------------------------
echo "==> Test 4: GetCommits (resolve by label)..."

COMMITS_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1.CommitService/GetCommits" \
  -H "Content-Type: application/json" \
  -d '{"resourceRefs": [{"owner": "acme", "module": "payments", "label": "main"}]}')

RESOLVED_ID=$(echo "$COMMITS_RESP" | jq -r '.commits[0].id')
if [ "$RESOLVED_ID" != "$COMMIT_ID" ]; then
  echo "ERROR: Label 'main' resolved to wrong commit: $RESOLVED_ID (expected $COMMIT_ID)"
  exit 1
fi
echo "  Label 'main' -> commit ${RESOLVED_ID:0:16}..."

# --------------------------------------------------------------------------
# Test 5: Download — fetch module content
# --------------------------------------------------------------------------
echo "==> Test 5: Download module (buf dep update equivalent)..."

DOWNLOAD_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1beta1.DownloadService/Download" \
  -H "Content-Type: application/json" \
  -d '{"values": [{"resourceRef": {"owner": "acme", "module": "payments", "label": "v1.0.0"}}]}')

FILE_COUNT=$(echo "$DOWNLOAD_RESP" | jq '.contents[0].files | length')
if [ "$FILE_COUNT" -lt 1 ]; then
  echo "ERROR: Download returned no files"
  echo "$DOWNLOAD_RESP"
  exit 1
fi
echo "  Downloaded $FILE_COUNT files"

# Verify proto file content round-trips correctly
DOWNLOADED_PROTO=$(echo "$DOWNLOAD_RESP" | jq -r '.contents[0].files[] | select(.path | contains(".proto")) | .content' | base64 -d 2>/dev/null || echo "$DOWNLOAD_RESP" | jq -r '.contents[0].files[] | select(.path | contains(".proto")) | .content' | base64 --decode)
if echo "$DOWNLOADED_PROTO" | grep -q "PaymentRequest"; then
  echo "  Proto content verified (PaymentRequest found)"
else
  echo "ERROR: Downloaded proto content doesn't match"
  exit 1
fi

# --------------------------------------------------------------------------
# Test 6: ListCommits — paginated listing
# --------------------------------------------------------------------------
echo "==> Test 6: ListCommits..."

LIST_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1.CommitService/ListCommits" \
  -H "Content-Type: application/json" \
  -d '{"owner": "acme", "module": "payments", "pageSize": 10}')

LIST_COUNT=$(echo "$LIST_RESP" | jq '.commits | length')
if [ "$LIST_COUNT" -lt 1 ]; then
  echo "ERROR: ListCommits returned no commits"
  exit 1
fi
echo "  Listed $LIST_COUNT commits"

# --------------------------------------------------------------------------
# Test 7: Idempotent re-upload (same content → same commit)
# --------------------------------------------------------------------------
echo "==> Test 7: Idempotent re-upload..."

REUPLOAD_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1beta1.UploadService/Upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPLOAD_BODY")

REUPLOAD_ID=$(echo "$REUPLOAD_RESP" | jq -r '.commits[0].id')
if [ "$REUPLOAD_ID" != "$COMMIT_ID" ]; then
  echo "ERROR: Re-upload returned different commit ID"
  exit 1
fi
echo "  Idempotent: same commit ${REUPLOAD_ID:0:16}..."

# --------------------------------------------------------------------------
# Test 8: GetResources — combined resolution
# --------------------------------------------------------------------------
echo "==> Test 8: GetResources..."

RESOURCES_RESP=$(curl -sf -X POST \
  "$REGISTRY_URL/proto/$REPO_KEY/buf.registry.module.v1.ResourceService/GetResources" \
  -H "Content-Type: application/json" \
  -d '{"resourceRefs": [{"owner": "acme", "module": "payments", "label": "main"}]}')

RESOURCE_MODULE=$(echo "$RESOURCES_RESP" | jq -r '.resources[0].module.name')
if [ "$RESOURCE_MODULE" != "payments" ]; then
  echo "ERROR: GetResources returned unexpected module: $RESOURCE_MODULE"
  exit 1
fi
echo "  Resource resolved: acme/$RESOURCE_MODULE"

# --------------------------------------------------------------------------
# Test 9: Write rejection on remote repo
# --------------------------------------------------------------------------
echo "==> Test 9: Write rejection on remote repo..."

# Create a remote protobuf repo
curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"proto-remote","name":"Proto Remote","format":"protobuf","repo_type":"remote","upstream_url":"https://buf.build","is_public":true}' \
  >/dev/null 2>&1 || true

REJECT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$REGISTRY_URL/proto/proto-remote/buf.registry.module.v1beta1.UploadService/Upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPLOAD_BODY")

if [ "$REJECT_STATUS" = "405" ]; then
  echo "  Remote repo correctly rejected upload (405)"
else
  echo "ERROR: Expected 405 for remote repo upload, got $REJECT_STATUS"
  exit 1
fi

echo ""
echo "=============================================="
echo "  All 9 Protobuf/BSR tests PASSED"
echo "=============================================="
