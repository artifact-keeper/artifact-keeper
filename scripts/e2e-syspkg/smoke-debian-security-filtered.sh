#!/usr/bin/env bash
# Smoke-test Artifact Keeper Debian remote mirror against Ubuntu or Debian security.
#
# Modes exercised:
#   1) passthrough — Release reachable before/after config (remote proxy)
#   2) filtered sync — main/amd64 + package_queries (curl*, ca-certificates) + deps
#   3) atomic generation — after sync, uncovered paths 404 (no mixed metadata)
#   4) apt client installs curl using AK as the security pocket
#
# Usage:
#   API_URL=http://127.0.0.1:8080 ADMIN_USER=admin ADMIN_PASS='...' \
#     ./scripts/e2e-syspkg/smoke-debian-security-filtered.sh
#
#   # Debian bookworm-security instead of Ubuntu noble-security:
#   CLIENT_DISTRO=debian ./scripts/e2e-syspkg/smoke-debian-security-filtered.sh
#
#   # Run both Ubuntu and Debian clients sequentially:
#   ./scripts/e2e-syspkg/smoke-debian-security-filtered.sh --both
set -euo pipefail

if [[ "${1:-}" == "--both" ]]; then
  echo "######## Ubuntu noble-security smoke ########"
  CLIENT_DISTRO=ubuntu "$0"
  echo
  echo "######## Debian bookworm-security smoke ########"
  CLIENT_DISTRO=debian "$0"
  echo
  echo "==> BOTH SMOKES OK"
  exit 0
fi

API_URL="${API_URL:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-ChangeMeNow!123}"
CLIENT_DISTRO="${CLIENT_DISTRO:-ubuntu}"

case "$CLIENT_DISTRO" in
  ubuntu)
    REPO_KEY="${REPO_KEY:-ubuntu-security-smoke}"
    UPSTREAM_URL="${UPSTREAM_URL:-http://security.ubuntu.com/ubuntu}"
    DIST="${DIST:-noble-security}"
    ARCHIVE_SUITE="${ARCHIVE_SUITE:-noble}"
    ARCHIVE_URL="${ARCHIVE_URL:-http://archive.ubuntu.com/ubuntu}"
    ROOTFS="${ROOTFS:-/tmp/ak-apt-rootfs-ubuntu}"
    # Prefer legacy path if already bootstrapped by earlier runs.
    if [[ ! -d "$ROOTFS/bin" && -d /tmp/ak-apt-rootfs/bin ]]; then
      ROOTFS=/tmp/ak-apt-rootfs
    fi
    DOCKER_IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"
    REPO_NAME="Ubuntu Security Smoke"
    ;;
  debian)
    REPO_KEY="${REPO_KEY:-debian-security-smoke}"
    UPSTREAM_URL="${UPSTREAM_URL:-http://security.debian.org/debian-security}"
    DIST="${DIST:-bookworm-security}"
    ARCHIVE_SUITE="${ARCHIVE_SUITE:-bookworm}"
    ARCHIVE_URL="${ARCHIVE_URL:-http://deb.debian.org/debian}"
    ROOTFS="${ROOTFS:-/tmp/ak-apt-rootfs-debian}"
    DOCKER_IMAGE="${DOCKER_IMAGE:-debian:bookworm-slim}"
    REPO_NAME="Debian Security Smoke"
    ;;
  *)
    echo "Unknown CLIENT_DISTRO=$CLIENT_DISTRO (use ubuntu|debian)"
    exit 1
    ;;
esac

need() { command -v "$1" >/dev/null || { echo "missing $1"; exit 1; }; }
need curl
need jq
need rg

echo "==> Client distro: $CLIENT_DISTRO ($DIST via $UPSTREAM_URL)"
echo "==> Login"
LOGIN=$(curl -sf -X POST "$API_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
TOKEN=$(echo "$LOGIN" | jq -r '.access_token // empty')
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "Login failed: $LOGIN"
  exit 1
fi
AUTH="Authorization: Bearer $TOKEN"

echo "==> Ensure remote Debian repo $REPO_KEY"
EXISTING=$(curl -sf -H "$AUTH" "$API_URL/api/v1/repositories" \
  | jq -r --arg k "$REPO_KEY" '.items[]? | select(.key==$k) | .key' | head -1)

BODY=$(cat <<JSON
{
  "name": "$REPO_NAME",
  "key": "$REPO_KEY",
  "format": "debian",
  "repo_type": "remote",
  "allow_anonymous_access": true,
  "upstream_url": "$UPSTREAM_URL",
  "debian": {
    "distribution_paths": ["$DIST"],
    "components": ["main"],
    "architectures": ["amd64"],
    "include_source_packages": false,
    "flat_repository": false,
    "verify_upstream_metadata": false,
    "metadata_strategy": "filter_and_generate",
    "package_fetch_strategy": "cache_on_request",
    "package_queries": ["curl*", "ca-certificates"],
    "resolve_dependencies": true,
    "ignore_missing_indexes": true
  }
}
JSON
)

if [[ -z "$EXISTING" ]]; then
  CREATE=$(curl -sf -X POST -H "$AUTH" -H 'Content-Type: application/json' \
    "$API_URL/api/v1/repositories" -d "$BODY")
  echo "$CREATE" | jq '{id,key,repo_type,debian:(.debian|{metadata_strategy,package_queries,components,architectures})}'
else
  echo "Repo exists: $EXISTING — updating debian config"
  curl -sf -X PATCH -H "$AUTH" -H 'Content-Type: application/json' \
    "$API_URL/api/v1/repositories/$REPO_KEY" \
    -d "$(echo "$BODY" | jq '{debian,allow_anonymous_access,upstream_url}')" >/dev/null
fi

echo "==> Release reachable (passthrough or published generation)"
CODE=$(curl -s -o /tmp/ak-release.txt -w '%{http_code}' \
  "$API_URL/debian/$REPO_KEY/dists/$DIST/Release" || true)
echo "GET Release => HTTP $CODE"
[[ "$CODE" == "200" ]] || { echo "Release failed"; head -20 /tmp/ak-release.txt; exit 1; }
head -8 /tmp/ak-release.txt

echo "==> Sync (filtered generate)"
SYNC=$(curl -sf -X POST -H "$AUTH" --max-time 900 "$API_URL/debian/$REPO_KEY/sync")
echo "$SYNC" | jq '{repository, prefetched_packages, prefetched_sources, plans: (.plans|length), selected_packages: (.plans[0].package_files|length)}'

echo "==> Atomic generation: Release must be local-generated / coherent"
CODE=$(curl -s -o /tmp/ak-release2.txt -w '%{http_code}' \
  "$API_URL/debian/$REPO_KEY/dists/$DIST/Release")
echo "GET Release after sync => HTTP $CODE"
[[ "$CODE" == "200" ]] || exit 1
rg -q '^Origin: artifact-keeper' /tmp/ak-release2.txt
rg -q '^Components:.*main' /tmp/ak-release2.txt
rg -q '^Architectures:.*amd64' /tmp/ak-release2.txt

echo "==> Uncovered path must 404 after generation (no upstream leak)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/debian/$REPO_KEY/dists/$DIST/universe/binary-amd64/Packages" || true)
echo "GET universe Packages => HTTP $CODE (expect 404)"
[[ "$CODE" == "404" ]] || { echo "expected 404 for excluded component"; exit 1; }

echo "==> Packages index for main/amd64 present and filtered"
CODE=$(curl -s -o /tmp/ak-packages.txt -w '%{http_code}' \
  "$API_URL/debian/$REPO_KEY/dists/$DIST/main/binary-amd64/Packages")
echo "GET Packages => HTTP $CODE size=$(wc -c </tmp/ak-packages.txt)"
[[ "$CODE" == "200" ]] || exit 1
PKG_COUNT=$(rg -c '^Package: ' /tmp/ak-packages.txt || echo 0)
echo "package stanzas: $PKG_COUNT"
[[ "$PKG_COUNT" -gt 0 ]] || { echo "empty Packages index"; exit 1; }
[[ "$PKG_COUNT" -lt 500 ]] || {
  echo "Packages still looks unfiltered ($PKG_COUNT stanzas)"; exit 1;
}
rg -q '^Package: curl$' /tmp/ak-packages.txt
if rg -q '^Package: ca-certificates$' /tmp/ak-packages.txt; then
  echo "ca-certificates present in filtered index"
elif [[ "$CLIENT_DISTRO" == "debian" ]]; then
  # Debian-Security often has no ca-certificates update; the base archive
  # suite supplies it during apt install. curl* + deps is enough to prove
  # filtered sync against the security pocket.
  echo "NOTE: ca-certificates not in ${DIST}; base archive will supply it"
else
  echo "missing Package: ca-certificates in filtered index"
  exit 1
fi
! rg -q '^Package: nginx$' /tmp/ak-packages.txt || {
  echo "unexpected nginx in filtered Packages"; exit 1;
}

echo "==> Out-of-filter pool path must 404"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/debian/$REPO_KEY/pool/main/n/nginx/nginx_1.0_amd64.deb" || true)
echo "GET nginx pool => HTTP $CODE (expect 404)"
[[ "$CODE" == "404" ]] || { echo "expected 404 for out-of-filter package"; exit 1; }

echo "==> Pool fetch for a selected package succeeds (on-demand cache)"
CURL_FILE=$(awk '
  $0 == "Package: curl" {in_pkg=1; next}
  in_pkg && /^Filename: / {print $2; exit}
  in_pkg && /^Package: / {exit}
' /tmp/ak-packages.txt)
[[ -n "$CURL_FILE" ]] || { echo "curl Filename missing"; exit 1; }
CODE=$(curl -s -o /tmp/ak-curl.deb -w '%{http_code}' "$API_URL/debian/$REPO_KEY/$CURL_FILE")
echo "GET $CURL_FILE => HTTP $CODE size=$(wc -c </tmp/ak-curl.deb)"
[[ "$CODE" == "200" ]] || exit 1

run_apt_client_chroot() {
  local ak_base="$1"
  local root="$2"

  # Dual sources: archive supplies transitive deps that live only in the base
  # suite, while AK is the sole security pocket (filtered partial sync).
  sudo rm -f "$root/etc/apt/sources.list" "$root/etc/apt/sources.list.d"/* 2>/dev/null || true
  sudo mkdir -p "$root/etc/apt/sources.list.d"
  cat <<EOF | sudo tee "$root/etc/apt/sources.list" >/dev/null
deb ${ARCHIVE_URL} ${ARCHIVE_SUITE} main
deb [trusted=yes arch=amd64] ${ak_base} ${DIST} main
EOF
  sudo cp /etc/resolv.conf "$root/etc/resolv.conf"

  sudo mount --bind /proc "$root/proc" 2>/dev/null || true
  sudo mount --bind /sys "$root/sys" 2>/dev/null || true
  sudo mount --bind /dev "$root/dev" 2>/dev/null || true

  local status=0
  sudo chroot "$root" bash -lc "
    set -euo pipefail
    apt-get update
    apt-cache policy curl | tee /tmp/curl-policy.txt
    grep -q '${DIST}' /tmp/curl-policy.txt
    CAND=\$(apt-cache policy curl | awk '/Candidate:/ {print \$2; exit}')
    echo \"curl candidate: \$CAND\"
    test -n \"\$CAND\"
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl
    curl --version | head -1
    if apt-cache madison nginx 2>/dev/null | grep -q '${DIST}'; then
      echo 'FAIL: nginx should not come from filtered ${DIST} on AK'
      apt-cache madison nginx || true
      exit 1
    fi
    echo 'filtered security index correctly omits nginx'
  " || status=$?

  sudo umount "$root/proc" 2>/dev/null || true
  sudo umount "$root/sys" 2>/dev/null || true
  sudo umount "$root/dev" 2>/dev/null || true
  return "$status"
}

run_apt_client_docker() {
  local ak_base="$1"
  sudo docker rm -f "ak-apt-smoke-${CLIENT_DISTRO}" >/dev/null 2>&1 || true
  sudo docker pull "$DOCKER_IMAGE" >/dev/null
  sudo docker run -d --name "ak-apt-smoke-${CLIENT_DISTRO}" \
    --add-host=host.docker.internal:host-gateway "$DOCKER_IMAGE" sleep 3600 >/dev/null
  sudo docker exec "ak-apt-smoke-${CLIENT_DISTRO}" bash -lc "
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq ca-certificates >/dev/null
    rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/* /etc/apt/sources.list
    cat >/etc/apt/sources.list <<EOF
deb ${ARCHIVE_URL} ${ARCHIVE_SUITE} main
deb [trusted=yes arch=amd64] ${ak_base} ${DIST} main
EOF
    apt-get update
    apt-cache policy curl | head -20
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl
    curl --version | head -1
    if apt-cache madison nginx 2>/dev/null | grep -q '${DIST}'; then
      echo 'FAIL: nginx visible from filtered ${DIST}'
      exit 1
    fi
    echo 'filtered security index correctly omits nginx'
  "
}

echo "==> ${CLIENT_DISTRO} apt client smoke against AK ${DIST} mirror"
DOCKER_OK=0
if command -v docker >/dev/null && sudo docker info >/dev/null 2>&1; then
  if sudo docker run --rm --add-host=host.docker.internal:host-gateway "$DOCKER_IMAGE" true >/dev/null 2>&1; then
    DOCKER_OK=1
  else
    echo "NOTE: docker run unavailable (overlay mount); using chroot rootfs"
  fi
fi

if [[ "$DOCKER_OK" == "1" ]]; then
  AK_APT_BASE="http://host.docker.internal:8080/debian/$REPO_KEY"
  run_apt_client_docker "$AK_APT_BASE"
else
  if [[ ! -d "$ROOTFS/bin" ]]; then
    need debootstrap
    echo "Bootstrapping ${CLIENT_DISTRO} rootfs at $ROOTFS (one-time)..."
    sudo debootstrap --variant=minbase --include=ca-certificates,apt-utils \
      "$ARCHIVE_SUITE" "$ROOTFS" "$ARCHIVE_URL"
  fi
  AK_HOST_PORT=$(echo "$API_URL" | sed -E 's#https?://##')
  AK_APT_BASE="http://${AK_HOST_PORT}/debian/$REPO_KEY"
  run_apt_client_chroot "$AK_APT_BASE" "$ROOTFS"
fi

echo "==> SMOKE OK ($CLIENT_DISTRO / $DIST)"
echo "UI:  http://127.0.0.1:3000  (admin / ChangeMeNow!123)"
echo "API: $API_URL"
echo "APT: deb [trusted=yes] $API_URL/debian/$REPO_KEY $DIST main"
