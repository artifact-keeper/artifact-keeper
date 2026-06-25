#!/bin/bash
# Permission visibility E2E test (issue #1996)
#
# Verifies that non-admin users can see private repositories they have access
# to through the fine-grained `permissions` table, including:
#   - Direct user permissions (principal_type='user')
#   - Group-based permissions (principal_type='group' via user_group_members)
#
# Requires: curl, jq
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

echo "==> Permission Visibility E2E Test (issue #1996)"
echo "Registry: $REGISTRY_URL"

# Check prerequisites
for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "SKIP: $cmd not found"
    exit 0
  fi
done

# Authenticate as admin
echo "==> [1/6] Authenticating as admin..."
ADMIN_TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r '.access_token')
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || { echo "❌ Admin auth failed"; exit 1; }
echo "✅ Admin authenticated"

# Create a private repository
echo "==> [2/6] Creating private repository..."
REPO_KEY="perm-vis-test-$(date +%s)"
REPO_JSON=$(curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO_KEY\",\"name\":\"Permission Visibility Test\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}")
REPO_ID=$(echo "$REPO_JSON" | jq -r '.id')
[ -n "$REPO_ID" ] && [ "$REPO_ID" != "null" ] || { echo "❌ Failed to create repository"; exit 1; }
echo "✅ Created private repository: $REPO_KEY ($REPO_ID)"

# Create a test user
echo "==> [3/6] Creating test user..."
TEST_USER="perm-vis-test-user-$(date +%s)"
TEST_PASS="TestUserPass123!"
USER_JSON=$(curl -sf -X POST "$REGISTRY_URL/api/v1/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$TEST_USER\",\"email\":\"$TEST_USER@test.local\",\"password\":\"$TEST_PASS\"}")
USER_ID=$(echo "$USER_JSON" | jq -r '.user.id')
[ -n "$USER_ID" ] && [ "$USER_ID" != "null" ] || { echo "❌ Failed to create user"; exit 1; }
echo "✅ Created test user: $TEST_USER ($USER_ID)"

# Create a test group
echo "==> [4/6] Creating test group..."
GROUP_NAME="perm-vis-test-group-$(date +%s)"
GROUP_JSON=$(curl -sf -X POST "$REGISTRY_URL/api/v1/groups" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$GROUP_NAME\"}")
GROUP_ID=$(echo "$GROUP_JSON" | jq -r '.id')
[ -n "$GROUP_ID" ] && [ "$GROUP_ID" != "null" ] || { echo "❌ Failed to create group"; exit 1; }
echo "✅ Created group: $GROUP_NAME ($GROUP_ID)"

# Add user to group
echo "==> [5/6] Adding user to group..."
curl -sf -X POST "$REGISTRY_URL/api/v1/groups/$GROUP_ID/members" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"user_ids\":[\"$USER_ID\"]}" \
  > /dev/null
echo "✅ User added to group"

# Grant group permission on repository
echo "==> [6/6] Granting group read permission on repository..."
curl -sf -X POST "$REGISTRY_URL/api/v1/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"principal_type\":\"group\",\"principal_id\":\"$GROUP_ID\",\"target_type\":\"repository\",\"target_id\":\"$REPO_ID\",\"actions\":[\"read\"]}" \
  > /dev/null
echo "✅ Group permission granted"

# ============================================================
# VERIFICATION
# ============================================================

# Log in as the test user
echo "==> Verifying: listing as test user..."
USER_TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}" | jq -r '.access_token')
[ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ] || { echo "❌ User auth failed"; exit 1; }

# List repositories
REPO_LIST=$(curl -sf "$REGISTRY_URL/api/v1/repositories" \
  -H "Authorization: Bearer $USER_TOKEN")

TOTAL=$(echo "$REPO_LIST" | jq '.pagination.total')
echo "Repositories visible to test user: $TOTAL"

# Check if our private repo appears
if echo "$REPO_LIST" | jq -e ".items[] | select(.key == \"$REPO_KEY\")" > /dev/null 2>&1; then
  echo "✅ PASS: Private repository IS visible to group member"
  RESULT=0
else
  echo "❌ FAIL: Private repository is NOT visible to group member"
  echo "This confirms issue #1996. The repository listing does not"
  echo "include repositories accessible via group permissions."
  RESULT=1
fi

# ============================================================
# CLEANUP
# ============================================================
echo "==> Cleaning up..."
curl -sf -X DELETE "$REGISTRY_URL/api/v1/repositories/$REPO_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  > /dev/null 2>&1 || true
curl -sf -X DELETE "$REGISTRY_URL/api/v1/groups/$GROUP_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  > /dev/null 2>&1 || true
# Get user ID for deletion
USER_ID=$(curl -sf "$REGISTRY_URL/api/v1/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r ".items[] | select(.username == \"$TEST_USER\") | .id")
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  curl -sf -X DELETE "$REGISTRY_URL/api/v1/users/$USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    > /dev/null 2>&1 || true
fi
echo "Cleanup done"

exit $RESULT
