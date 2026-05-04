#!/bin/sh
# Bootstrap Dependency-Track: change default password and provision API key.
# Runs as an init container, writes the API key to a shared volume.
#
# Requires: curl, jq (use alpine/curl + apk add jq, or similar)
# Idempotent: safe to run multiple times.
#
# Bug #978: Dependency-Track 4.x no longer exposes existing key material on
# `GET /api/v1/team` — only `maskedKey` is returned for previously-created
# keys. The unmasked key is only ever returned in the response body of
# `POST /api/v1/team/<uuid>/key`. We must therefore *create* a fresh key
# and capture the response, rather than try to read an existing one.
#
# Idempotence strategy: on each run we delete every existing key on the
# Automation team (using `publicId` from the GET listing) and then POST a
# new one. This keeps the team to a single active key across reruns and
# prevents accumulation across helm upgrades.
set -e

DT_URL="${DEPENDENCY_TRACK_URL:-http://dependency-track-apiserver:8080}"
DT_ADMIN_USER="admin"
DT_DEFAULT_PASS="admin"
DT_NEW_PASS="${DEPENDENCY_TRACK_ADMIN_PASSWORD:-ArtifactKeeper2026!}"
API_KEY_FILE="/shared/dtrack-api-key"
BOOTSTRAP_MARKER="/shared/.dtrack-bootstrapped"

echo "[dtrack-init] Waiting for Dependency-Track at $DT_URL ..."
for i in $(seq 1 60); do
  if curl -sf "$DT_URL/api/version" > /dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "[dtrack-init] ERROR: Dependency-Track did not become ready in 5 minutes" >&2
    exit 1
  fi
  sleep 5
done
echo "[dtrack-init] Dependency-Track is up"

# If API key file already exists from a previous run, skip all provisioning.
# This is the fast path on helm upgrades — we don't rotate unless the shared
# volume has been wiped.
if [ -f "$API_KEY_FILE" ] && [ -s "$API_KEY_FILE" ]; then
  echo "[dtrack-init] API key already provisioned at $API_KEY_FILE — skipping"
  exit 0
fi

# Try login with the new password first (already changed in a previous partial run)
TOKEN=$(curl -sf -X POST "$DT_URL/api/v1/user/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${DT_ADMIN_USER}&password=${DT_NEW_PASS}" 2>/dev/null || true)

if [ -z "$TOKEN" ] || echo "$TOKEN" | grep -qi "FORCE_PASSWORD_CHANGE"; then
  # First boot: change the default admin password
  echo "[dtrack-init] Changing default admin password..."
  CHANGE_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$DT_URL/api/v1/user/forceChangePassword" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=${DT_DEFAULT_PASS}&newPassword=${DT_NEW_PASS}&confirmPassword=${DT_NEW_PASS}")

  if [ "$CHANGE_RESULT" != "200" ]; then
    echo "[dtrack-init] WARNING: Password change returned HTTP $CHANGE_RESULT (may already be changed)"
  fi

  # Login with new password
  TOKEN=$(curl -sf -X POST "$DT_URL/api/v1/user/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=${DT_NEW_PASS}" 2>/dev/null || true)
fi

if [ -z "$TOKEN" ]; then
  echo "[dtrack-init] ERROR: Could not authenticate with Dependency-Track" >&2
  exit 1
fi

echo "[dtrack-init] Authenticated successfully"

# Look up the Automation team's UUID and existing key publicIds.
# DT 4.x only returns `maskedKey` and `publicId` for existing keys, so we
# can't extract the actual secret here — we use this only to identify the
# team and to enumerate stale keys for rotation.
TEAM_JSON=$(curl -sf "$DT_URL/api/v1/team" -H "Authorization: Bearer $TOKEN" || true)
if [ -z "$TEAM_JSON" ]; then
  echo "[dtrack-init] ERROR: Could not list teams" >&2
  exit 1
fi

TEAM_UUID=$(echo "$TEAM_JSON" | jq -r '.[] | select(.name == "Automation") | .uuid // empty')

if [ -z "$TEAM_UUID" ]; then
  echo "[dtrack-init] ERROR: Could not find Automation team" >&2
  echo "[dtrack-init] Available teams:" >&2
  echo "$TEAM_JSON" | jq -r '.[].name' >&2 2>/dev/null || true
  exit 1
fi
echo "[dtrack-init] Found Automation team: $TEAM_UUID"

# Rotate: delete every pre-existing key on the Automation team. Each helm
# upgrade that reaches this branch (i.e. shared volume is empty) starts
# fresh, preventing key accumulation. DELETE returns 204 on success;
# missing/already-gone keys are ignored.
EXISTING_PUBLIC_IDS=$(echo "$TEAM_JSON" | \
  jq -r '.[] | select(.name == "Automation") | .apiKeys[]?.publicId // empty')
if [ -n "$EXISTING_PUBLIC_IDS" ]; then
  echo "[dtrack-init] Rotating existing Automation API keys..."
  echo "$EXISTING_PUBLIC_IDS" | while IFS= read -r PUBLIC_ID; do
    [ -z "$PUBLIC_ID" ] && continue
    DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "$DT_URL/api/v1/team/$TEAM_UUID/key/$PUBLIC_ID" \
      -H "Authorization: Bearer $TOKEN")
    case "$DEL_CODE" in
      204|404) ;;  # gone (success) or already gone — both fine
      *) echo "[dtrack-init] WARNING: DELETE key $PUBLIC_ID returned HTTP $DEL_CODE" ;;
    esac
  done
fi

# Create a fresh API key. DT 4.x returns the unmasked secret in the
# response body of this single call — there is no other way to retrieve it.
echo "[dtrack-init] Generating new Automation API key..."
KEY_RESP=$(curl -sf -X POST "$DT_URL/api/v1/team/$TEAM_UUID/key" \
  -H "Authorization: Bearer $TOKEN" || true)

if [ -z "$KEY_RESP" ]; then
  echo "[dtrack-init] ERROR: POST /api/v1/team/$TEAM_UUID/key returned empty body" >&2
  exit 1
fi

API_KEY=$(echo "$KEY_RESP" | jq -r '.key // empty')

if [ -z "$API_KEY" ]; then
  echo "[dtrack-init] ERROR: Could not extract .key from create-key response" >&2
  echo "[dtrack-init] Response was: $KEY_RESP" >&2
  exit 1
fi

# Write to a temp file in the same directory then rename, so consumers
# never see a half-written key.
TMP_KEY_FILE="$API_KEY_FILE.tmp"
printf '%s' "$API_KEY" > "$TMP_KEY_FILE"
chmod 644 "$TMP_KEY_FILE"
mv "$TMP_KEY_FILE" "$API_KEY_FILE"
echo "[dtrack-init] API key written to $API_KEY_FILE"

# Enable NVD API 2.0 mirroring (NIST retired legacy feeds; DTrack 4.10.0+ supports API 2.0)
echo "[dtrack-init] Enabling NVD API 2.0 vulnerability source..."
NVD_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$DT_URL/api/v1/configProperty" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"groupName":"vuln-source","propertyName":"nvd.feeds.url","propertyValue":"https://services.nvd.nist.gov/rest/json/cves/2.0"}')
if [ "$NVD_RESULT" = "200" ]; then
  echo "[dtrack-init] NVD API 2.0 source configured"
else
  echo "[dtrack-init] WARNING: NVD config returned HTTP $NVD_RESULT (may already be set or unsupported)"
fi

# Drop a marker so operators can tell at a glance that bootstrap completed.
: > "$BOOTSTRAP_MARKER" 2>/dev/null || true

echo "[dtrack-init] Done"
