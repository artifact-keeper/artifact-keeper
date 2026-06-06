#!/bin/sh
# Bootstrap Dependency-Track: change default password and provision API key.
# Runs as an init container, writes the API key to a shared volume.
#
# Requires: curl, jq
# Idempotent: safe to run multiple times.
#
# Dependency-Track 4.x no longer exposes existing key material on
# GET /api/v1/team. Only maskedKey is returned for previously-created
# keys. The unmasked key is only returned in the response body of
# PUT /api/v1/team/<uuid>/key.
#
# Idempotence strategy:
# - If /shared/dtrack-api-key already exists, do NOT rotate the key.
#   Instead, best-effort log in, find the team, ensure the required
#   permissions, and exit successfully.
# - If the key file does not exist, rotate/create the init-managed key,
#   write it to /shared/dtrack-api-key, and ensure permissions.
#
# Safety rail:
# If foreign publicIds are present on the Automation team, refuse to rotate
# unless DTRACK_INIT_FORCE_ROTATE=true is set. This prevents silently
# revoking operator-attached integration keys.

set -e

DT_URL="${DEPENDENCY_TRACK_URL:-http://dependency-track-apiserver:8080}"
DT_ADMIN_USER="admin"
DT_DEFAULT_PASS="admin"
DT_NEW_PASS="${DEPENDENCY_TRACK_ADMIN_PASSWORD:-ArtifactKeeper2026!}"
DT_TEAM_NAME="Automation"

API_KEY_FILE="/shared/dtrack-api-key"
BOOTSTRAP_MARKER="/shared/.dtrack-bootstrapped"
PUBLIC_ID_MARKER="/shared/.dtrack-publicid"
FORCE_ROTATE="${DTRACK_INIT_FORCE_ROTATE:-false}"

REQUIRED_PERMISSIONS="
BOM_UPLOAD
PROJECT_CREATION_UPLOAD
VIEW_PORTFOLIO
VIEW_VULNERABILITY
PORTFOLIO_MANAGEMENT
"

dt_login() {
  curl -sf -X POST "$DT_URL/api/v1/user/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=$1" 2>/dev/null || true
}

ensure_team_permissions() {
  REQUIRED_MODE="${1:-required}"
  echo "[dtrack-init] Granting required permissions to $DT_TEAM_NAME team..."

  for PERM in $REQUIRED_PERMISSIONS; do
    PERM_CODE=$(curl -s -o /tmp/dtrack-permission-response.txt -w "%{http_code}" \
      -X POST "$DT_URL/api/v1/permission/$PERM/team/$TEAM_UUID" \
      -H "Authorization: Bearer $TOKEN")

    case "$PERM_CODE" in
      200|201|204|304|409)
        echo "[dtrack-init]   - $PERM: ensured (HTTP $PERM_CODE)"
        ;;
      *)
        if [ "$REQUIRED_MODE" = "best-effort" ]; then
          echo "[dtrack-init]   WARNING: granting $PERM returned HTTP $PERM_CODE; continuing because API key already exists" >&2
        else
          echo "[dtrack-init]   ERROR: granting $PERM returned HTTP $PERM_CODE" >&2
        fi
        echo "[dtrack-init]   Response:" >&2
        cat /tmp/dtrack-permission-response.txt >&2 || true
        if [ "$REQUIRED_MODE" = "best-effort" ]; then
          continue
        fi
        exit 1
        ;;
    esac
  done
}

finish_existing_key_path() {
  : > "$BOOTSTRAP_MARKER" 2>/dev/null || true
  echo "[dtrack-init] Existing API key preserved; done"
  exit 0
}

API_KEY_ALREADY_PROVISIONED=false

if [ -f "$API_KEY_FILE" ] && [ -s "$API_KEY_FILE" ]; then
  echo "[dtrack-init] API key already provisioned at $API_KEY_FILE; will best-effort verify team permissions"
  API_KEY_ALREADY_PROVISIONED=true
  if [ "$FORCE_ROTATE" = "true" ]; then
    echo "[dtrack-init] DTRACK_INIT_FORCE_ROTATE=true; existing API key will be rotated"
    API_KEY_ALREADY_PROVISIONED=false
  fi
fi

echo "[dtrack-init] Waiting for Dependency-Track at $DT_URL ..."
for i in $(seq 1 60); do
  if curl -sf "$DT_URL/api/version" > /dev/null 2>&1; then
    break
  fi

  if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
    echo "[dtrack-init] WARNING: Dependency-Track is not reachable; keeping existing API key and skipping permission verification" >&2
    finish_existing_key_path
  fi

  if [ "$i" -eq 60 ]; then
    echo "[dtrack-init] ERROR: Dependency-Track did not become ready in 5 minutes" >&2
    exit 1
  fi

  sleep 5
done
echo "[dtrack-init] Dependency-Track is up"

# Try login with the new password first.
TOKEN=$(dt_login "$DT_NEW_PASS")

if [ -z "$TOKEN" ] || echo "$TOKEN" | grep -qi "FORCE_PASSWORD_CHANGE"; then
  if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
    echo "[dtrack-init] WARNING: Could not authenticate with Dependency-Track admin credentials; keeping existing API key and skipping permission verification" >&2
    finish_existing_key_path
  fi

  echo "[dtrack-init] Changing default admin password..."

  CHANGE_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$DT_URL/api/v1/user/forceChangePassword" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=${DT_DEFAULT_PASS}&newPassword=${DT_NEW_PASS}&confirmPassword=${DT_NEW_PASS}" || true)

  if [ "$CHANGE_RESULT" != "200" ]; then
    echo "[dtrack-init] WARNING: Password change returned HTTP $CHANGE_RESULT (may already be changed)"
  fi

  TOKEN=$(dt_login "$DT_NEW_PASS")
fi

if [ -z "$TOKEN" ]; then
  if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
    echo "[dtrack-init] WARNING: Could not authenticate with Dependency-Track; keeping existing API key and skipping permission verification" >&2
    finish_existing_key_path
  fi
  echo "[dtrack-init] ERROR: Could not authenticate with Dependency-Track" >&2
  exit 1
fi

echo "[dtrack-init] Authenticated successfully"

TEAM_JSON=$(curl -sf "$DT_URL/api/v1/team" -H "Authorization: Bearer $TOKEN" || true)

if [ -z "$TEAM_JSON" ]; then
  if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
    echo "[dtrack-init] WARNING: Could not list teams; keeping existing API key and skipping permission verification" >&2
    finish_existing_key_path
  fi
  echo "[dtrack-init] ERROR: Could not list teams" >&2
  exit 1
fi

TEAM_UUID=$(echo "$TEAM_JSON" | jq -r --arg name "$DT_TEAM_NAME" \
  '.[] | select(.name == $name) | .uuid // empty')

if [ -z "$TEAM_UUID" ]; then
  if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
    echo "[dtrack-init] WARNING: Could not find $DT_TEAM_NAME team; keeping existing API key and skipping permission verification" >&2
    finish_existing_key_path
  fi
  echo "[dtrack-init] ERROR: Could not find $DT_TEAM_NAME team" >&2
  echo "[dtrack-init] Available teams:" >&2
  echo "$TEAM_JSON" | jq -r '.[].name' 2>/dev/null >&2 || true
  exit 1
fi

echo "[dtrack-init] Found $DT_TEAM_NAME team: $TEAM_UUID"

# If the API key already exists, only ensure permissions and exit.
# This fixes the previous bootstrap bug where the script exited before
# granting permissions on existing deployments.
if [ "$API_KEY_ALREADY_PROVISIONED" = "true" ]; then
  ensure_team_permissions best-effort
  echo "[dtrack-init] Existing API key permissions verified; done"
  finish_existing_key_path
fi

EXISTING_PUBLIC_IDS=$(echo "$TEAM_JSON" | jq -r --arg name "$DT_TEAM_NAME" \
  '.[] | select(.name == $name) | .apiKeys[]?.publicId // empty')

OUR_PUBLIC_ID=""
if [ -s "$PUBLIC_ID_MARKER" ]; then
  OUR_PUBLIC_ID=$(cat "$PUBLIC_ID_MARKER")
fi

if [ -n "$EXISTING_PUBLIC_IDS" ]; then
  if [ -n "$OUR_PUBLIC_ID" ]; then
    FOREIGN_PUBLIC_IDS=$(echo "$EXISTING_PUBLIC_IDS" | grep -Fxv -- "$OUR_PUBLIC_ID" || true)
  else
    FOREIGN_PUBLIC_IDS="$EXISTING_PUBLIC_IDS"
  fi

  if [ -n "$FOREIGN_PUBLIC_IDS" ] && [ "$FORCE_ROTATE" != "true" ]; then
    echo "[dtrack-init] ERROR: refusing to rotate $DT_TEAM_NAME team — foreign API key(s) present:" >&2
    echo "$FOREIGN_PUBLIC_IDS" | sed 's/^/[dtrack-init]   - publicId=/' >&2
    echo "[dtrack-init] These keys were not minted by dtrack-init and may belong to" >&2
    echo "[dtrack-init] external integrations. Silently revoking them would break those" >&2
    echo "[dtrack-init] integrations with no audit trail." >&2
    echo "[dtrack-init] To proceed, EITHER remove the foreign keys via the DT UI" >&2
    echo "[dtrack-init] Administration -> Teams -> $DT_TEAM_NAME -> API Keys" >&2
    echo "[dtrack-init] OR set DTRACK_INIT_FORCE_ROTATE=true to acknowledge revocation." >&2
    exit 2
  fi

  if [ -n "$FOREIGN_PUBLIC_IDS" ]; then
    echo "[dtrack-init] WARNING: DTRACK_INIT_FORCE_ROTATE=true — revoking foreign keys:" >&2
    echo "$FOREIGN_PUBLIC_IDS" | sed 's/^/[dtrack-init]   - publicId=/' >&2
  fi

  echo "[dtrack-init] Rotating existing $DT_TEAM_NAME API keys..."

  echo "$EXISTING_PUBLIC_IDS" | while IFS= read -r PUBLIC_ID; do
    [ -z "$PUBLIC_ID" ] && continue

    DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "$DT_URL/api/v1/team/$TEAM_UUID/key/$PUBLIC_ID" \
      -H "Authorization: Bearer $TOKEN")

    case "$DEL_CODE" in
      204|404)
        ;;
      *)
        echo "[dtrack-init] WARNING: DELETE key $PUBLIC_ID returned HTTP $DEL_CODE" >&2
        ;;
    esac
  done
fi

echo "[dtrack-init] Generating new $DT_TEAM_NAME API key..."

KEY_RESP=$(curl -sf -X PUT "$DT_URL/api/v1/team/$TEAM_UUID/key" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" || true)

if [ -z "$KEY_RESP" ]; then
  echo "[dtrack-init] ERROR: PUT /api/v1/team/$TEAM_UUID/key returned empty body" >&2
  exit 1
fi

API_KEY=$(echo "$KEY_RESP" | jq -r '.key // empty')
NEW_PUBLIC_ID=$(echo "$KEY_RESP" | jq -r '.publicId // empty')

if [ -z "$API_KEY" ]; then
  echo "[dtrack-init] ERROR: Could not extract .key from create-key response" >&2
  echo "[dtrack-init] Response length: ${#KEY_RESP} bytes" >&2
  RESP_KEYS=$(echo "$KEY_RESP" | jq -r 'keys // []' 2>/dev/null || echo '<not-json>')
  echo "[dtrack-init] Response top-level keys: $RESP_KEYS" >&2
  exit 1
fi

if [ -z "$NEW_PUBLIC_ID" ]; then
  echo "[dtrack-init] ERROR: Could not extract .publicId from create-key response" >&2
  exit 1
fi

TMP_KEY_FILE="$API_KEY_FILE.tmp"
(
  umask 077
  printf '%s' "$API_KEY" > "$TMP_KEY_FILE"
)
chmod 600 "$TMP_KEY_FILE"
mv "$TMP_KEY_FILE" "$API_KEY_FILE"

echo "[dtrack-init] API key written to $API_KEY_FILE (mode 0600)"

TMP_PUBLIC_ID_MARKER="$PUBLIC_ID_MARKER.tmp"
(
  umask 077
  printf '%s' "$NEW_PUBLIC_ID" > "$TMP_PUBLIC_ID_MARKER"
)
chmod 600 "$TMP_PUBLIC_ID_MARKER"
mv "$TMP_PUBLIC_ID_MARKER" "$PUBLIC_ID_MARKER"

ensure_team_permissions

echo "[dtrack-init] Enabling NVD REST API 2.0 mirroring..."

NVD_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$DT_URL/api/v1/configProperty" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"groupName":"vuln-source","propertyName":"nvd.api.enabled","propertyValue":"true"}' || true)

if [ "$NVD_RESULT" = "200" ] || [ "$NVD_RESULT" = "201" ] || [ "$NVD_RESULT" = "204" ]; then
  echo "[dtrack-init] NVD REST API 2.0 mirroring enabled"
else
  echo "[dtrack-init] WARNING: NVD API config returned HTTP $NVD_RESULT (may already be set)"
fi

: > "$BOOTSTRAP_MARKER" 2>/dev/null || true

echo "[dtrack-init] Done"
