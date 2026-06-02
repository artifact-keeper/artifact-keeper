#!/bin/sh
# Bootstrap Dependency-Track: change default password and provision API key.
# Runs as an init container, writes the API key to a shared volume.
#
# Requires: curl, jq (use alpine/curl + apk add jq, or similar)
# Idempotent: safe to run multiple times.
#
# Bug #978: Dependency-Track 4.x no longer exposes existing key material on
# `GET /api/v1/team`. Only `maskedKey` is returned for previously-created
# keys. The unmasked key is only ever returned in the response body of
# `PUT /api/v1/team/<uuid>/key`. We must therefore *create* a fresh key
# and capture the response, rather than try to read an existing one.
#
# Idempotence strategy: on each run we delete the publicId we previously
# minted (recorded in PUBLIC_ID_MARKER) and then PUT a new one. This keeps
# the team to a single active key across reruns and prevents accumulation
# across helm upgrades.
#
# Safety rail (#1041 follow-up): if any publicId is present on the team that
# we did NOT mint (no marker, or marker mismatch), refuse to rotate and exit
# non-zero. This prevents the silent revocation of operator-attached
# integration keys. Set DTRACK_INIT_FORCE_ROTATE=true to acknowledge and
# proceed (e.g. during a planned, documented rotation).
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

# Login against /api/v1/user/login. DT returns a bare JWT string body on
# success and a body containing "FORCE_PASSWORD_CHANGE" when the default
# password has not yet been rotated. The caller decides which response is
# acceptable; we just echo the body.
dt_login() {
  curl -sf -X POST "$DT_URL/api/v1/user/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=$1" 2>/dev/null || true
}

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

# If the API key file already exists from a previous run we skip the
# rotate/mint path below, but we still log in and re-apply the permission
# grants (#1530). Operators upgrading from a pre-#1511 build have a valid
# key on the shared volume but the team behind it has none of the four
# permissions the AK integration needs, so the integration silently fails
# on every PUT /api/v1/project until the team is granted BOM_UPLOAD,
# PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO, VIEW_VULNERABILITY. The grants
# are idempotent (POST returns 200 on first grant, 304 on subsequent calls)
# so re-running them on the fast path is safe.
KEY_ALREADY_PROVISIONED=false
if [ -f "$API_KEY_FILE" ] && [ -s "$API_KEY_FILE" ]; then
  echo "[dtrack-init] API key already provisioned at $API_KEY_FILE, skipping rotation"
  KEY_ALREADY_PROVISIONED=true
fi

# Try login with the new password first (already changed in a previous partial run)
TOKEN=$(dt_login "$DT_NEW_PASS")

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
  TOKEN=$(dt_login "$DT_NEW_PASS")
fi

if [ -z "$TOKEN" ]; then
  echo "[dtrack-init] ERROR: Could not authenticate with Dependency-Track" >&2
  exit 1
fi

echo "[dtrack-init] Authenticated successfully"

# Look up the Automation team's UUID and existing key publicIds.
# DT 4.x only returns `maskedKey` and `publicId` for existing keys, so we
# can't extract the actual secret here. We use this only to identify the
# team and to enumerate stale keys for rotation.
TEAM_JSON=$(curl -sf "$DT_URL/api/v1/team" -H "Authorization: Bearer $TOKEN" || true)
if [ -z "$TEAM_JSON" ]; then
  echo "[dtrack-init] ERROR: Could not list teams" >&2
  exit 1
fi

TEAM_UUID=$(echo "$TEAM_JSON" | jq -r --arg name "$DT_TEAM_NAME" \
  '.[] | select(.name == $name) | .uuid // empty')

if [ -z "$TEAM_UUID" ]; then
  echo "[dtrack-init] ERROR: Could not find $DT_TEAM_NAME team" >&2
  echo "[dtrack-init] Available teams:" >&2
  echo "$TEAM_JSON" | jq -r '.[].name' 2>/dev/null >&2 || true
  exit 1
fi
echo "[dtrack-init] Found $DT_TEAM_NAME team: $TEAM_UUID"

if [ "$KEY_ALREADY_PROVISIONED" = "false" ]; then

# Rotate: delete the publicId we previously minted (tracked in
# PUBLIC_ID_MARKER), then PUT a new one below.
#
# Safety rail: if the team has publicIds we did NOT mint, those may belong
# to operator-attached integrations (CI scanners, dashboards, webhooks).
# Silently revoking them would break those integrations with no audit
# trail. Refuse and require explicit operator acknowledgment via
# DTRACK_INIT_FORCE_ROTATE=true.
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
    echo "[dtrack-init] (Administration -> Teams -> $DT_TEAM_NAME -> API Keys)" >&2
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
      204|404) ;;  # gone (success) or already gone, both fine
      *) echo "[dtrack-init] WARNING: DELETE key $PUBLIC_ID returned HTTP $DEL_CODE" ;;
    esac
  done
fi

# Create a fresh API key. DT 4.x returns the unmasked secret in the
# response body of this single call. There is no other way to retrieve it.
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
  # Do NOT log $KEY_RESP. If the schema ever moves .key (e.g. to .data.key)
  # the unmasked secret is in that body and would leak to log aggregation.
  # Log only structural diagnostics.
  echo "[dtrack-init] ERROR: Could not extract .key from create-key response" >&2
  echo "[dtrack-init] Response length: ${#KEY_RESP} bytes" >&2
  RESP_KEYS=$(echo "$KEY_RESP" | jq -r 'keys // []' 2>/dev/null || echo '<not-json>')
  echo "[dtrack-init] Response top-level keys: $RESP_KEYS" >&2
  exit 1
fi

if [ -z "$NEW_PUBLIC_ID" ]; then
  # publicId is required to track ownership for the next rotation cycle.
  # Without it we cannot distinguish our own key from a foreign key on
  # subsequent runs and would refuse to rotate (refuse-by-default guard).
  echo "[dtrack-init] ERROR: Could not extract .publicId from create-key response" >&2
  exit 1
fi

# Defense-in-depth (#1038): the key file holds an unmasked DT API key.
# Container isolation prevents cross-container access, but tightening the
# in-container mode to 0600 (owner read/write only) blocks any in-container
# unprivileged process or sidecar from reading it. The backend reads the
# file as the same UID that wrote it, so 0600 is sufficient.
#
# Use `umask 077` BEFORE the redirect rather than write-then-chmod so
# the secret is never briefly readable on disk. Write to a temp file in
# the same directory then rename, so consumers never see a half-written key.
TMP_KEY_FILE="$API_KEY_FILE.tmp"
(
  umask 077
  printf '%s' "$API_KEY" > "$TMP_KEY_FILE"
)
chmod 600 "$TMP_KEY_FILE"
mv "$TMP_KEY_FILE" "$API_KEY_FILE"
echo "[dtrack-init] API key written to $API_KEY_FILE (mode 0600)"

# Record the publicId we just minted so the next rotation cycle can
# distinguish our key from operator-attached foreign keys.
#
# Atomicity: write to .tmp + rename so a crash mid-write cannot leave an
# empty or truncated marker — that would cause the next run to classify
# our own key as foreign and refuse to rotate.
#
# Threat model: the marker is read at line ~127 (`cat $PUBLIC_ID_MARKER`)
# and trusted as the answer to "which publicId did we mint?". Anyone with
# write access to /shared can therefore spoof ownership and trick a future
# rotation into silently revoking a foreign key. /shared is expected to
# be exclusively writable by this init container's UID; we tighten the
# marker to mode 0600 (umask 077 in the subshell) as defense-in-depth so
# a co-tenant sidecar that gains read access cannot also clobber it.
TMP_PUBLIC_ID_MARKER="$PUBLIC_ID_MARKER.tmp"
(
  umask 077
  printf '%s' "$NEW_PUBLIC_ID" > "$TMP_PUBLIC_ID_MARKER"
)
chmod 600 "$TMP_PUBLIC_ID_MARKER"
mv "$TMP_PUBLIC_ID_MARKER" "$PUBLIC_ID_MARKER"

fi  # end: rotate/mint block (skipped on fast path)

# Grant the DT team the permissions the backend integration depends on
# (#1472, #1530). Without these, SBOM uploads from the scan pipeline
# silently 401/403 and DT stays empty even when AK scans look green. The DT
# default Automation team has NONE of these permissions.
#
# This runs UNCONDITIONALLY, including on the fast path where the API key
# was minted by a pre-#1511 build. Operators upgrading from an older bundle
# had a valid key but a team with no permissions; without re-applying the
# grants on every boot, the upgrade path would never repair itself (#1530).
# The DT permission endpoint is idempotent: POST returns 200 on first
# grant and 304 on subsequent calls, so repeated invocations are cheap.
#
# Source of truth for the permission list lives in
# backend/src/services/dependency_track_service.rs (module docs + the
# DT_PERMISSIONS_HINT constant). Keep these in sync.
echo "[dtrack-init] Granting required permissions to $DT_TEAM_NAME team..."
for PERM in BOM_UPLOAD PROJECT_CREATION_UPLOAD VIEW_PORTFOLIO VIEW_VULNERABILITY; do
  PERM_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$DT_URL/api/v1/permission/$PERM/team/$TEAM_UUID" \
    -H "Authorization: Bearer $TOKEN")
  case "$PERM_CODE" in
    200|304)
      echo "[dtrack-init]   - $PERM: granted (HTTP $PERM_CODE)"
      ;;
    *)
      # Don't exit non-zero on a single grant failure: an already-granted
      # permission may return non-2xx on some DT versions, and a transient
      # error should not block bootstrap. The backend logs a clear
      # permissions hint on every 401/403 (see dependency_track_service.rs)
      # so a genuinely-missing grant is still operator-visible.
      echo "[dtrack-init]   WARNING: granting $PERM returned HTTP $PERM_CODE" >&2
      ;;
  esac
done

echo "[dtrack-init] Enabling NVD REST API 2.0 mirroring..."
NVD_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$DT_URL/api/v1/configProperty" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"groupName":"vuln-source","propertyName":"nvd.api.enabled","propertyValue":"true"}')
if [ "$NVD_RESULT" = "200" ]; then
  echo "[dtrack-init] NVD REST API 2.0 mirroring enabled"
else
  echo "[dtrack-init] WARNING: NVD API config returned HTTP $NVD_RESULT (may already be set)"
fi

# Drop a marker so operators can tell at a glance that bootstrap completed.
: > "$BOOTSTRAP_MARKER" 2>/dev/null || true

echo "[dtrack-init] Done"
