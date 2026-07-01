#!/usr/bin/env bash
# Terraform/OpenTofu network-mirror archive download regression test (#1998).
#
# This is a black-box reproduction of:
#
#   GET /terraform/<repo>/registry.terraform.io/hashicorp/null/3.2.3/download/linux/arm64
#   -> historically 400 "Invalid artifact path"
#
# The failure only appears on the network-mirror archive endpoint: service
# discovery, index.json, and <version>.json all work first. The archive endpoint
# must fetch the registry-provided absolute download_url but cache it under a
# safe local path.
#
# Usage against the local E2E backend:
#   ./scripts/native-tests/test-terraform-mirror.sh
#
# Usage against a live instance with a token:
#   REGISTRY_URL=https://ak.cazlab.link AK_TOKEN=... \
#     TF_OS=linux TF_ARCH=arm64 ./scripts/native-tests/test-terraform-mirror.sh
#
# Usage against an existing remote repo without creating/deleting it:
#   REGISTRY_URL=https://ak.cazlab.link AK_TOKEN=... TF_REPO_KEY=my-tf-remote \
#     CREATE_TF_REPO=0 ./scripts/native-tests/test-terraform-mirror.sh
#
# The real Terraform CLI phase runs automatically when `terraform` is present.
# Use RUN_TERRAFORM_CLI=1 to require it, or RUN_TERRAFORM_CLI=0 for HTTP-only.
#
# Requires: bash, curl, jq, od, wc. Optional: terraform.
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
REGISTRY_URL="${REGISTRY_URL%/}"
API_URL="$REGISTRY_URL/api/v1"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
TOKEN="${AK_TOKEN:-${ARTIFACT_KEEPER_TOKEN:-}}"

TF_UPSTREAM_URL="${TF_UPSTREAM_URL:-https://registry.terraform.io}"
TF_UPSTREAM_URL="${TF_UPSTREAM_URL%/}"
host_from_upstream="${TF_UPSTREAM_URL#http://}"
host_from_upstream="${host_from_upstream#https://}"
host_from_upstream="${host_from_upstream%%/*}"
TF_HOSTNAME="${TF_HOSTNAME:-$host_from_upstream}"

TF_NAMESPACE="${TF_NAMESPACE:-hashicorp}"
TF_TYPE="${TF_TYPE:-null}"
TF_VERSION="${TF_VERSION:-3.2.3}"
TF_OS="${TF_OS:-linux}"
TF_ARCH="${TF_ARCH:-amd64}"
CURL_MAX_TIME="${CURL_MAX_TIME:-120}"
RUN_TERRAFORM_CLI="${RUN_TERRAFORM_CLI:-auto}"
TERRAFORM_BIN="${TERRAFORM_BIN:-terraform}"

if [ -n "${TF_REPO_KEY:-}" ]; then
    REPO_KEY="$TF_REPO_KEY"
    CREATE_TF_REPO="${CREATE_TF_REPO:-0}"
else
    REPO_KEY="tf-mirror-1998-$(date +%s)-$$"
    CREATE_TF_REPO="${CREATE_TF_REPO:-1}"
fi

KEEP_TF_REPO="${KEEP_TF_REPO:-0}"
RECREATE_TF_REPO="${RECREATE_TF_REPO:-0}"
CREATED_REPO=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0
SKIPPED=0

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $1"; SKIPPED=$((SKIPPED + 1)); }

TMPDIR_TEST="$(mktemp -d)"
AUTH_ARGS=()

cleanup() {
    rm -rf "$TMPDIR_TEST"

    if [ "$CREATED_REPO" = "1" ] && [ "$KEEP_TF_REPO" != "1" ]; then
        curl -sS -o /dev/null -X DELETE "$API_URL/repositories/$REPO_KEY" \
            "${AUTH_ARGS[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1"
        exit 1
    fi
}

require_cmd curl
require_cmd jq
require_cmd od
require_cmd wc

host_from_url() {
    local url="$1"
    url="${url#http://}"
    url="${url#https://}"
    url="${url%%/*}"
    printf '%s' "$url"
}

curl_code() {
    local out="$1"
    local url="$2"
    local code

    if ! code=$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" \
        "${AUTH_ARGS[@]}" "$url"); then
        code="000"
    fi
    printf '%s' "$code"
}

body_preview() {
    local file="$1"
    if [ ! -s "$file" ]; then
        printf '<empty>'
        return
    fi
    tr '\n' ' ' < "$file" | cut -c 1-240
}

authenticate() {
    echo "==> Authenticating..."

    if [ -n "$TOKEN" ]; then
        AUTH_ARGS=(-H "Authorization: Bearer $TOKEN")
        pass "using bearer token from AK_TOKEN/ARTIFACT_KEEPER_TOKEN"
        echo ""
        return
    fi

    local login_body="$TMPDIR_TEST/login.json"
    local login_code
    if ! login_code=$(curl -sS --max-time "$CURL_MAX_TIME" -o "$login_body" -w "%{http_code}" \
        -X POST "$API_URL/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}"); then
        login_code="000"
    fi

    if [ "$login_code" != "200" ]; then
        echo "ERROR: authentication failed with HTTP $login_code"
        echo "Set AK_TOKEN/ARTIFACT_KEEPER_TOKEN, or ADMIN_USER/ADMIN_PASS."
        echo "Response: $(body_preview "$login_body")"
        exit 1
    fi

    TOKEN="$(jq -r '.access_token // empty' "$login_body")"
    if [ -z "$TOKEN" ]; then
        echo "ERROR: login response did not include access_token"
        exit 1
    fi

    AUTH_ARGS=(-H "Authorization: Bearer $TOKEN")
    pass "logged in as $ADMIN_USER"
    echo ""
}

create_remote_repo() {
    if [ "$CREATE_TF_REPO" != "1" ]; then
        skip "using existing Terraform remote repo '$REPO_KEY'"
        return
    fi

    echo "==> Creating Terraform remote repo..."

    if [ "$RECREATE_TF_REPO" = "1" ]; then
        curl -sS -o /dev/null -X DELETE "$API_URL/repositories/$REPO_KEY" \
            "${AUTH_ARGS[@]}" 2>/dev/null || true
    fi

    local repo_body="$TMPDIR_TEST/create-repo.json"
    local payload
    payload=$(jq -n \
        --arg key "$REPO_KEY" \
        --arg name "Terraform Mirror 1998 Regression" \
        --arg upstream "$TF_UPSTREAM_URL" \
        '{
            key: $key,
            name: $name,
            format: "terraform",
            repo_type: "remote",
            is_public: true,
            upstream_url: $upstream
        }')

    local code
    if ! code=$(curl -sS --max-time "$CURL_MAX_TIME" -o "$repo_body" -w "%{http_code}" \
        -X POST "$API_URL/repositories" \
        "${AUTH_ARGS[@]}" \
        -H 'Content-Type: application/json' \
        -d "$payload"); then
        code="000"
    fi

    case "$code" in
        200|201)
            CREATED_REPO=1
            pass "created remote repo '$REPO_KEY' -> $TF_UPSTREAM_URL"
            ;;
        *)
            echo "ERROR: failed to create repo '$REPO_KEY' (HTTP $code)"
            echo "Response: $(body_preview "$repo_body")"
            exit 1
            ;;
    esac
    echo ""
}

assert_json_200() {
    local label="$1"
    local url="$2"
    local jq_expr="$3"
    shift 3
    local out="$TMPDIR_TEST/$label.json"
    local code

    code=$(curl_code "$out" "$url")
    if [ "$code" != "200" ]; then
        fail "$label returned HTTP $code (expected 200): $(body_preview "$out")"
        return
    fi

    if jq -e "$@" "$jq_expr" "$out" >/dev/null 2>&1; then
        pass "$label returned 200 with expected JSON"
    else
        fail "$label returned 200 but JSON did not match: $(body_preview "$out")"
    fi
}

assert_archive_download() {
    local label="$1"
    local url="$2"
    local out="$TMPDIR_TEST/$label.zip"
    local code
    local bytes
    local magic

    code=$(curl_code "$out" "$url")
    bytes=$(wc -c < "$out" | tr -d ' ')

    if [ "$code" != "200" ]; then
        if [ "$code" = "400" ]; then
            fail "$label returned HTTP 400; this reproduces #1998: $(body_preview "$out")"
        else
            fail "$label returned HTTP $code (expected 200): $(body_preview "$out")"
        fi
        return
    fi

    magic=$(head -c 4 "$out" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        504b0304|504b0506|504b0708)
            pass "$label returned a zip archive (HTTP 200, ${bytes} bytes)"
            ;;
        *)
            fail "$label returned 200 but did not look like a zip (magic=$magic, bytes=$bytes)"
            ;;
    esac
}

terraform_source_address() {
    if [ "$TF_HOSTNAME" = "registry.terraform.io" ]; then
        printf '%s/%s' "$TF_NAMESPACE" "$TF_TYPE"
    else
        printf '%s/%s/%s' "$TF_HOSTNAME" "$TF_NAMESPACE" "$TF_TYPE"
    fi
}

run_terraform_cli_init() {
    case "$RUN_TERRAFORM_CLI" in
        0|false|False|FALSE|no|No|NO)
            skip "terraform CLI phase disabled by RUN_TERRAFORM_CLI=$RUN_TERRAFORM_CLI"
            return
            ;;
        auto)
            if ! command -v "$TERRAFORM_BIN" >/dev/null 2>&1; then
                skip "terraform CLI phase skipped; '$TERRAFORM_BIN' not found"
                return
            fi
            ;;
        1|true|True|TRUE|yes|Yes|YES)
            if ! command -v "$TERRAFORM_BIN" >/dev/null 2>&1; then
                fail "terraform CLI phase requested, but '$TERRAFORM_BIN' was not found"
                return
            fi
            ;;
        *)
            fail "invalid RUN_TERRAFORM_CLI value '$RUN_TERRAFORM_CLI' (use auto, 1, or 0)"
            return
            ;;
    esac

    echo "==> Running Terraform CLI network_mirror init..."

    local tf_work="$TMPDIR_TEST/terraform-cli"
    local tf_config="$tf_work/terraformrc"
    local tf_plugin_cache="$tf_work/plugin-cache"
    local tf_out="$TMPDIR_TEST/terraform-init.out"
    local mirror_url="$REGISTRY_URL/terraform/$REPO_KEY/"
    local mirror_include="$TF_HOSTNAME/$TF_NAMESPACE/$TF_TYPE"
    local source_addr
    local registry_host

    source_addr="$(terraform_source_address)"
    registry_host="$(host_from_url "$REGISTRY_URL")"

    mkdir -p "$tf_work" "$tf_plugin_cache"

    cat > "$tf_work/main.tf" <<EOF
terraform {
  required_providers {
    subject = {
      source  = "$source_addr"
      version = "$TF_VERSION"
    }
  }
}
EOF

    cat > "$tf_config" <<EOF
credentials "$registry_host" {
  token = "$TOKEN"
}

provider_installation {
  network_mirror {
    url     = "$mirror_url"
    include = ["$mirror_include"]
  }

  direct {
    exclude = ["$mirror_include"]
  }
}
EOF

    if TF_CLI_CONFIG_FILE="$tf_config" \
        TF_DATA_DIR="$tf_work/.terraform" \
        TF_PLUGIN_CACHE_DIR="$tf_plugin_cache" \
        CHECKPOINT_DISABLE=1 \
        "$TERRAFORM_BIN" -chdir="$tf_work" init -input=false -no-color >"$tf_out" 2>&1; then
        pass "terraform init installed $source_addr $TF_VERSION through network_mirror"
        return
    fi

    if grep -Eq 'bad response code: 400|Invalid artifact path|Failed to install provider' "$tf_out"; then
        fail "terraform init failed through network_mirror; this reproduces #1998: $(body_preview "$tf_out")"
    else
        fail "terraform init failed: $(body_preview "$tf_out")"
    fi
}

echo "=============================================="
echo "Terraform/OpenTofu Mirror Archive E2E (#1998)"
echo "=============================================="
echo "Registry:       $REGISTRY_URL"
echo "Repo key:       $REPO_KEY"
echo "Upstream:       $TF_UPSTREAM_URL"
echo "Mirror host:    $TF_HOSTNAME"
echo "Provider:       $TF_NAMESPACE/$TF_TYPE $TF_VERSION ($TF_OS/$TF_ARCH)"
echo "Create repo:    $CREATE_TF_REPO"
echo "Terraform CLI:  $RUN_TERRAFORM_CLI ($TERRAFORM_BIN)"
echo ""

authenticate
create_remote_repo

SERVICE_URL="$REGISTRY_URL/terraform/$REPO_KEY/.well-known/terraform.json"
INDEX_URL="$REGISTRY_URL/terraform/$REPO_KEY/$TF_HOSTNAME/$TF_NAMESPACE/$TF_TYPE/index.json"
VERSION_URL="$REGISTRY_URL/terraform/$REPO_KEY/$TF_HOSTNAME/$TF_NAMESPACE/$TF_TYPE/$TF_VERSION.json"
DOWNLOAD_URL="$REGISTRY_URL/terraform/$REPO_KEY/$TF_HOSTNAME/$TF_NAMESPACE/$TF_TYPE/$TF_VERSION/download/$TF_OS/$TF_ARCH"

echo "==> Exercising network-mirror protocol..."
assert_json_200 "service-discovery" "$SERVICE_URL" 'has("providers.v1")'
assert_json_200 "provider-index" "$INDEX_URL" '.versions[$version] != null' \
    --arg version "$TF_VERSION"
assert_json_200 "provider-version" "$VERSION_URL" \
    '.archives[$archive_key].url != null' --arg archive_key "${TF_OS}_${TF_ARCH}"
assert_archive_download "provider-archive" "$DOWNLOAD_URL"
assert_archive_download "provider-archive-second-fetch" "$DOWNLOAD_URL"
run_terraform_cli_init
echo ""

echo "=============================================="
echo "Terraform Mirror Test Summary"
echo "=============================================="
echo "Passed:  $PASSED"
echo "Failed:  $FAILED"
echo "Skipped: $SKIPPED"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "Result: FAILED"
    exit 1
fi

echo ""
echo "Result: PASSED"
