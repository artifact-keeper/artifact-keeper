#!/usr/bin/env bash
# Terraform/OpenTofu hosted module install regression test (#4590).
#
# Hosted modules could not be installed by `tofu init` / `terraform init`:
# `.../download` answered `204` with an `X-Terraform-Get` location that carried
# no archive type hint, so the client's getter fetched it as an HTML page
# looking for a `terraform-get` meta tag and failed on the archive bytes
# ("XML syntax error ... illegal character code U+0003").
#
# This test publishes a ZIP module and a tar.gz module to a hosted repo, checks
# the protocol answers over HTTP, then runs the real CLI against each module
# source `<host>/<namespace>/<name>/<provider>`.
#
# Module source addresses have no room for a path prefix, and the client only
# probes `https://<host>/.well-known/terraform.json`, so the CLI phase puts a
# small Caddy in front of the backend that rewrites that discovery path to the
# repo's own discovery document and forwards `/terraform/*` (the documented
# rewrite from #3838). Caddy serves HTTPS from its internal CA, and the CLI is
# pointed at that CA with SSL_CERT_FILE.
#
# Usage against the local E2E backend:
#   ./scripts/native-tests/test-terraform-modules.sh
#
# Usage against any backend with a token:
#   REGISTRY_URL=http://127.0.0.1:8080 AK_TOKEN=... \
#     ./scripts/native-tests/test-terraform-modules.sh
#
# The CLI phase runs when a client (`tofu`, else `terraform`; override with
# TF_CLI_BIN) and `caddy` (CADDY_BIN) are present, and is skipped cleanly
# otherwise. RUN_TF_CLI=1 requires it; RUN_TF_CLI=0 runs the HTTP checks only.
#
# MODULE_HOST must resolve to 127.0.0.1 (`*.localhost` names do on most
# systems; when running as root the script adds an /etc/hosts entry if not).
#
# Requires: bash, curl, jq, od, tar, gzip, zip. Optional: tofu or terraform,
# caddy.
set -uo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
REGISTRY_URL="${REGISTRY_URL%/}"
API_URL="$REGISTRY_URL/api/v1"

ADMIN_USER="${ADMIN_USER:-admin}"
# Throwaway e2e admin credential: the value is defined once, in the
# repository-root .env.test (#3490). Absent inside an e2e container, where
# compose has already injected the same variables from the same file.
_ak_test_env="$(dirname "$0")/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"
TOKEN="${AK_TOKEN:-${ARTIFACT_KEEPER_TOKEN:-}}"

TF_NAMESPACE="${TF_NAMESPACE:-acme}"
TF_PROVIDER="${TF_PROVIDER:-aws}"
TF_VERSION="${TF_VERSION:-1.0.0}"
MODULE_HOST="${MODULE_HOST:-tfmod.localhost}"
PROXY_PORT="${PROXY_PORT:-18443}"
CURL_MAX_TIME="${CURL_MAX_TIME:-60}"
RUN_TF_CLI="${RUN_TF_CLI:-auto}"
CADDY_BIN="${CADDY_BIN:-caddy}"
if [ -z "${TF_CLI_BIN:-}" ]; then
    if command -v tofu >/dev/null 2>&1; then
        TF_CLI_BIN=tofu
    else
        TF_CLI_BIN=terraform
    fi
fi

REPO_KEY="${TF_REPO_KEY:-tf-modules-4590-$(date +%s)-$$}"
KEEP_TF_REPO="${KEEP_TF_REPO:-0}"
CREATED_REPO=0
CADDY_PID=""

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
    if [ -n "$CADDY_PID" ]; then
        kill "$CADDY_PID" 2>/dev/null || true
        wait "$CADDY_PID" 2>/dev/null || true
    fi
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

for cmd in curl jq od tar gzip zip; do
    require_cmd "$cmd"
done

host_from_url() {
    local url="$1"
    url="${url#http://}"
    url="${url#https://}"
    url="${url%%/*}"
    printf '%s' "$url"
}

body_preview() {
    local file="$1"
    if [ ! -s "$file" ]; then
        printf '<empty>'
        return
    fi
    tr '\n' ' ' < "$file" | cut -c 1-300
}

magic_of() {
    head -c 4 "$1" | od -An -tx1 | tr -d ' \n'
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

create_hosted_repo() {
    echo "==> Creating Terraform hosted repo..."

    local repo_body="$TMPDIR_TEST/create-repo.json"
    local payload code
    payload=$(jq -n --arg key "$REPO_KEY" '{
        key: $key,
        name: "Terraform Modules 4590 Regression",
        format: "terraform",
        repo_type: "local",
        is_public: true
    }')

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
            pass "created hosted repo '$REPO_KEY'"
            ;;
        *)
            echo "ERROR: failed to create repo '$REPO_KEY' (HTTP $code)"
            echo "Response: $(body_preview "$repo_body")"
            exit 1
            ;;
    esac
    echo ""
}

# Build one module directory with a single output, so `init` has something to
# install and the installed copy can be checked for it.
make_module_dir() {
    local dir="$1"
    local name="$2"
    mkdir -p "$dir"
    cat > "$dir/main.tf" <<EOF
output "module_name" {
  value = "$name"
}
EOF
}

build_modules() {
    echo "==> Building module archives..."
    make_module_dir "$TMPDIR_TEST/src/zipmod" zipmod
    make_module_dir "$TMPDIR_TEST/src/tgzmod" tgzmod

    (cd "$TMPDIR_TEST/src/zipmod" && zip -q "$TMPDIR_TEST/zipmod.zip" main.tf)
    tar -C "$TMPDIR_TEST/src/tgzmod" -czf "$TMPDIR_TEST/tgzmod.tar.gz" main.tf
    printf '<html>not a module archive</html>' > "$TMPDIR_TEST/junk.bin"

    case "$(magic_of "$TMPDIR_TEST/zipmod.zip")" in
        504b0304) pass "built zipmod.zip" ;;
        *) fail "zip did not produce a ZIP archive"; return ;;
    esac
    case "$(magic_of "$TMPDIR_TEST/tgzmod.tar.gz")" in
        1f8b*) pass "built tgzmod.tar.gz" ;;
        *) fail "tar did not produce a gzip archive" ;;
    esac
    echo ""
}

module_url() {
    printf '%s/terraform/%s/v1/modules/%s/%s/%s/%s' \
        "$REGISTRY_URL" "$REPO_KEY" "$TF_NAMESPACE" "$1" "$TF_PROVIDER" "$TF_VERSION"
}

upload_module() {
    local name="$1"
    local file="$2"
    local expect="$3"
    local out="$TMPDIR_TEST/upload-$name.json"
    local code

    if ! code=$(curl -sS --max-time "$CURL_MAX_TIME" -o "$out" -w "%{http_code}" \
        -X PUT "${AUTH_ARGS[@]}" --data-binary "@$file" "$(module_url "$name")"); then
        code="000"
    fi

    if [ "$code" = "$expect" ]; then
        pass "upload $name returned HTTP $code"
    else
        fail "upload $name returned HTTP $code (expected $expect): $(body_preview "$out")"
    fi
}

# The protocol chain the CLI walks, over plain HTTP: `.../download` must answer
# 204 with an `X-Terraform-Get` carrying the archive hint, and that location
# must serve the archive with the matching type.
check_download_chain() {
    local name="$1"
    local hint="$2"
    local content_type="$3"
    local magic_prefix="$4"
    local headers="$TMPDIR_TEST/download-$name.headers"
    local code location archive_code archive_ct archive_out

    if ! code=$(curl -sS --max-time "$CURL_MAX_TIME" -D "$headers" -o /dev/null \
        -w "%{http_code}" "$(module_url "$name")/download"); then
        code="000"
    fi
    location=$(grep -i '^x-terraform-get:' "$headers" | head -1 | cut -d' ' -f2- | tr -d '\r')

    if [ "$code" != "204" ]; then
        fail "$name download returned HTTP $code (expected 204)"
        return
    fi
    case "$location" in
        *"/archive?archive=$hint")
            pass "$name X-Terraform-Get carries archive=$hint ($location)"
            ;;
        *)
            fail "$name X-Terraform-Get lacks the archive=$hint hint: '$location' (#4590)"
            return
            ;;
    esac

    archive_out="$TMPDIR_TEST/archive-$name"
    if ! archive_code=$(curl -sS --max-time "$CURL_MAX_TIME" -o "$archive_out" \
        -w "%{http_code} %{content_type}" "$REGISTRY_URL$location"); then
        archive_code="000"
    fi
    archive_ct="${archive_code#* }"
    archive_code="${archive_code%% *}"

    if [ "$archive_code" = "200" ] && [ "$archive_ct" = "$content_type" ] \
        && [[ "$(magic_of "$archive_out")" == "$magic_prefix"* ]]; then
        pass "$name archive served as $content_type"
    else
        fail "$name archive returned HTTP $archive_code, type '$archive_ct', magic $(magic_of "$archive_out")"
    fi
}

cli_phase_enabled() {
    case "$RUN_TF_CLI" in
        0|false|no)
            skip "CLI phase disabled by RUN_TF_CLI=$RUN_TF_CLI"
            return 1
            ;;
        auto|1|true|yes) ;;
        *)
            fail "invalid RUN_TF_CLI value '$RUN_TF_CLI' (use auto, 1, or 0)"
            return 1
            ;;
    esac

    local missing=""
    command -v "$TF_CLI_BIN" >/dev/null 2>&1 || missing="$TF_CLI_BIN"
    command -v "$CADDY_BIN" >/dev/null 2>&1 || missing="${missing:+$missing, }$CADDY_BIN"
    if [ -n "$missing" ]; then
        if [ "$RUN_TF_CLI" = "auto" ]; then
            skip "CLI phase skipped; not found: $missing"
        else
            fail "CLI phase requested, but not found: $missing"
        fi
        return 1
    fi
    return 0
}

ensure_module_host_resolves() {
    if getent hosts "$MODULE_HOST" >/dev/null 2>&1; then
        return 0
    fi
    if [ -w /etc/hosts ]; then
        echo "127.0.0.1 $MODULE_HOST" >> /etc/hosts
        return 0
    fi
    # Go's own resolver maps *.localhost to loopback even where the system
    # resolver does not, so carry on and let the CLI step report a failure.
    return 0
}

start_discovery_proxy() {
    local caddy_dir="$TMPDIR_TEST/caddy"
    local backend
    backend="$(host_from_url "$REGISTRY_URL")"
    mkdir -p "$caddy_dir/data"

    cat > "$caddy_dir/Caddyfile" <<EOF
{
	admin off
	skip_install_trust
	# No :80 redirect listener: unprivileged, and only HTTPS is used.
	auto_https disable_redirects
	storage file_system $caddy_dir/data
}

https://$MODULE_HOST:$PROXY_PORT {
	bind 127.0.0.1
	tls internal
	# Host-level discovery for this one repository (#3838 rewrite).
	rewrite /.well-known/terraform.json /terraform/$REPO_KEY/.well-known/terraform.json
	reverse_proxy /terraform/* $backend
}
EOF

    XDG_DATA_HOME="$caddy_dir/data" XDG_CONFIG_HOME="$caddy_dir" \
        "$CADDY_BIN" run --config "$caddy_dir/Caddyfile" --adapter caddyfile \
        >"$caddy_dir/caddy.log" 2>&1 &
    CADDY_PID=$!

    CA_CERT="$caddy_dir/data/pki/authorities/local/root.crt"
    local _
    for _ in $(seq 1 50); do
        if [ -s "$CA_CERT" ] && curl -sS --max-time 5 --cacert "$CA_CERT" \
            --resolve "$MODULE_HOST:$PROXY_PORT:127.0.0.1" -o /dev/null \
            "https://$MODULE_HOST:$PROXY_PORT/.well-known/terraform.json" 2>/dev/null; then
            break
        fi
        if ! kill -0 "$CADDY_PID" 2>/dev/null; then
            fail "caddy exited: $(body_preview "$caddy_dir/caddy.log")"
            return 1
        fi
        sleep 0.2
    done

    local disco="$TMPDIR_TEST/disco.json"
    if curl -sS --max-time 10 --cacert "$CA_CERT" \
        --resolve "$MODULE_HOST:$PROXY_PORT:127.0.0.1" -o "$disco" \
        "https://$MODULE_HOST:$PROXY_PORT/.well-known/terraform.json" \
        && jq -e 'has("modules.v1")' "$disco" >/dev/null 2>&1; then
        pass "discovery proxy serves https://$MODULE_HOST:$PROXY_PORT/.well-known/terraform.json"
    else
        fail "discovery proxy did not serve the discovery document: $(body_preview "$disco")"
        return 1
    fi
}

run_cli_init() {
    local name="$1"
    local work="$TMPDIR_TEST/cli-$name"
    local out="$TMPDIR_TEST/cli-$name.out"
    local source_addr="$MODULE_HOST:$PROXY_PORT/$TF_NAMESPACE/$name/$TF_PROVIDER"

    mkdir -p "$work"
    cat > "$work/main.tf" <<EOF
module "subject" {
  source  = "$source_addr"
  version = "$TF_VERSION"
}
EOF
    cat > "$work/cli.tfrc" <<EOF
credentials "$MODULE_HOST:$PROXY_PORT" {
  token = "$TOKEN"
}
EOF

    if SSL_CERT_FILE="$CA_CERT" \
        TF_CLI_CONFIG_FILE="$work/cli.tfrc" \
        TF_DATA_DIR="$work/.terraform" \
        CHECKPOINT_DISABLE=1 \
        "$TF_CLI_BIN" -chdir="$work" init -input=false -no-color >"$out" 2>&1 \
        && grep -q "\"$name\"" "$work/.terraform/modules/subject/main.tf" 2>/dev/null; then
        pass "$TF_CLI_BIN init installed $source_addr $TF_VERSION"
        return
    fi

    if grep -q 'XML syntax error' "$out"; then
        fail "$TF_CLI_BIN init parsed the module archive as HTML; this reproduces #4590: $(body_preview "$out")"
    else
        fail "$TF_CLI_BIN init failed for $source_addr: $(body_preview "$out")"
    fi
}

echo "=============================================="
echo "Terraform/OpenTofu Hosted Module Install (#4590)"
echo "=============================================="
echo "Registry:     $REGISTRY_URL"
echo "Repo key:     $REPO_KEY"
echo "Module host:  $MODULE_HOST:$PROXY_PORT"
echo "CLI:          $RUN_TF_CLI ($TF_CLI_BIN, proxy: $CADDY_BIN)"
echo ""

authenticate
create_hosted_repo
build_modules

echo "==> Publishing modules..."
upload_module zipmod "$TMPDIR_TEST/zipmod.zip" 201
upload_module tgzmod "$TMPDIR_TEST/tgzmod.tar.gz" 201
upload_module junkmod "$TMPDIR_TEST/junk.bin" 400
echo ""

echo "==> Exercising the module registry protocol..."
check_download_chain zipmod zip application/zip 504b0304
check_download_chain tgzmod tar.gz application/gzip 1f8b
echo ""

if cli_phase_enabled; then
    echo "==> Running $TF_CLI_BIN init through host-level discovery..."
    ensure_module_host_resolves
    if start_discovery_proxy; then
        run_cli_init zipmod
        run_cli_init tgzmod
    fi
fi
echo ""

echo "=============================================="
echo "Terraform Modules Test Summary"
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
