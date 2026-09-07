#!/bin/bash
# mise (aqua backend) GitHub-Releases proxy E2E test
#
# aqua packages are overwhelmingly `github_release` type: plain downloads from
# https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>. mise's
# aqua backend supports `settings.url_replacements` (mise >= v2025.9.3), which
# rewrites those URLs to an internal mirror. A `generic` remote repository
# pointed at https://github.com is that mirror — no aqua-specific server
# protocol exists or is needed. See docs/mise-aqua.md.
#
# This test intentionally hits the real github.com (same policy as
# test-pub-proxy.sh hitting the real pub.dev): the github.com ->
# objects.githubusercontent.com redirect hop is part of what's under test and
# cannot be exercised against a loopback mock (loopback redirect hops are
# hard-blocked by the SSRF policy).
#
# Out of scope (documented limitations): mise's version listing
# (api.github.com) and aqua registry metadata are not proxied — the mise step
# below pins an exact version so the asset download is the proxied traffic.
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
PROXY_REPO_KEY="${PROXY_REPO_KEY:-github-releases}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"

# A small, stable, multi-arch release used as the probe artifact.
JQ_TAG="jq-1.7.1"
JQ_ASSET="jq-linux-amd64"
JQ_PATH="jqlang/jq/releases/download/$JQ_TAG"

echo "==> mise / aqua GitHub-Releases Proxy E2E Test"
echo "Registry: $REGISTRY_URL"
echo "Proxy:    $PROXY_REPO_KEY"
echo ""

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---- Step 1: Create generic remote (proxy) repo ----
echo "==> [1/4] Creating generic remote repo for github.com..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/api/v1/repositories/$PROXY_REPO_KEY")

if [ "$HTTP_CODE" = "404" ]; then
  CREATE_RESP=$(curl -s -w "\n%{http_code}" \
    -u "$ADMIN_USER:$ADMIN_PASS" \
    -X POST "$REGISTRY_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -d "{
      \"key\": \"$PROXY_REPO_KEY\",
      \"name\": \"GitHub Releases Proxy\",
      \"format\": \"generic\",
      \"repo_type\": \"remote\",
      \"upstream_url\": \"https://github.com\",
      \"is_public\": true
    }")
  CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
  CREATE_BODY=$(echo "$CREATE_RESP" | sed '$d')
  echo "  Create response ($CREATE_STATUS): $CREATE_BODY"
  if [ "$CREATE_STATUS" -ge 300 ]; then
    echo "❌ Failed to create proxy repository"
    exit 1
  fi
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  Repository already exists"
else
  echo "  ⚠️  Unexpected status checking repo: $HTTP_CODE"
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ---- Step 2: Download a release asset through the proxy, verify integrity ----
echo ""
echo "==> [2/4] Downloading $JQ_ASSET through the proxy..."

ASSET_URL="$REGISTRY_URL/general/$PROXY_REPO_KEY/$JQ_PATH/$JQ_ASSET"
SUMS_URL="$REGISTRY_URL/general/$PROXY_REPO_KEY/$JQ_PATH/sha256sum.txt"

curl -fsSL -o "$WORK_DIR/$JQ_ASSET" "$ASSET_URL"
curl -fsSL -o "$WORK_DIR/sha256sum.txt" "$SUMS_URL"

EXPECTED_SHA=$(awk -v asset="$JQ_ASSET" '$2 == asset {print $1}' "$WORK_DIR/sha256sum.txt")
ACTUAL_SHA=$(sha256_of "$WORK_DIR/$JQ_ASSET")

if [ -z "$EXPECTED_SHA" ]; then
  echo "❌ Could not find $JQ_ASSET in upstream sha256sum.txt"
  exit 1
fi
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "❌ Checksum mismatch: expected $EXPECTED_SHA, got $ACTUAL_SHA"
  exit 1
fi
echo "  ✅ Asset downloaded via proxy, sha256 verified ($ACTUAL_SHA)"

# ---- Step 3: Second fetch must serve identical bytes (cache hit) ----
echo ""
echo "==> [3/4] Re-fetching to exercise the cache..."

curl -fsSL -o "$WORK_DIR/again-$JQ_ASSET" "$ASSET_URL"
SECOND_SHA=$(sha256_of "$WORK_DIR/again-$JQ_ASSET")
if [ "$SECOND_SHA" != "$EXPECTED_SHA" ]; then
  echo "❌ Cached fetch returned different bytes: $SECOND_SHA"
  exit 1
fi
echo "  ✅ Second fetch identical (served from proxy cache)"

# ---- Step 4: Real `mise install` through the proxy via url_replacements ----
echo ""
echo "==> [4/4] mise install through the proxy..."

MISE_EXIT=0
if command -v mise >/dev/null 2>&1; then
  # Fully hermetic mise environment: HOME is overridden so the developer's
  # own ~/mise.toml / ~/.config/mise are never read (an untrusted user config
  # aborts every mise command), and the working directory is the temp dir so
  # no repo-local mise.toml interferes.
  MISE_HOME="$WORK_DIR/mise-home"
  mkdir -p "$MISE_HOME/.config/mise"

  # Quoted heredoc + sed: keeps the TOML regex escaping (`github\\.com`) and
  # the `$1`/`$2`/`$3` capture references out of bash's hands.
  cat > "$MISE_HOME/.config/mise/config.toml" << 'EOF'
[settings.url_replacements]
"regex:^https://github\\.com/([^/]+)/([^/]+)/releases/download/(.+)" = "__REGISTRY__/general/__REPO__/$1/$2/releases/download/$3"
EOF
  sed -i.bak \
    -e "s|__REGISTRY__|$REGISTRY_URL|" \
    -e "s|__REPO__|$PROXY_REPO_KEY|" \
    "$MISE_HOME/.config/mise/config.toml" && rm -f "$MISE_HOME/.config/mise/config.toml.bak"

  run_mise() {
    (cd "$MISE_HOME" && HOME="$MISE_HOME" MISE_YES=1 mise "$@")
  }

  # url_replacements is security-sensitive, so mise requires the config file
  # to be explicitly trusted even at the global path.
  run_mise trust "$MISE_HOME/.config/mise/config.toml"

  # Pinned version: the asset download (proxied) is the traffic under test;
  # version listing via api.github.com is out of scope and avoided.
  if run_mise install "aqua:jqlang/jq@1.7.1"; then
    VERSION_OUT=$(run_mise exec "aqua:jqlang/jq@1.7.1" -- jq --version 2>&1 || true)
    echo "  jq --version: $VERSION_OUT"
    if echo "$VERSION_OUT" | grep -q "1.7.1"; then
      echo "  ✅ mise installed and ran jq through the proxy"
    else
      echo "  ❌ installed jq did not run correctly"
      MISE_EXIT=1
    fi
  else
    echo "  ❌ mise install failed"
    MISE_EXIT=1
  fi
else
  echo "  ⚠️  mise not on PATH — skipping the client step (curl steps above passed)"
fi

# ---- Summary ----
echo ""
echo "=============================================="
echo "MISE / AQUA PROXY TEST SUMMARY"
echo "=============================================="
echo "Proxy repo:    $PROXY_REPO_KEY"
echo "Asset:         $JQ_PATH/$JQ_ASSET"
echo "Checksum:      verified"
echo ""

if [ "$MISE_EXIT" -eq 0 ]; then
  echo "✅ mise/aqua proxy E2E test PASSED"
else
  echo "❌ mise/aqua proxy E2E test FAILED"
  exit 1
fi
