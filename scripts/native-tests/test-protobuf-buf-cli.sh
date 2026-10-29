#!/bin/bash
# Protobuf / BSR test driven by the real buf CLI.
#
# test-protobuf.sh exercises the same endpoints with curl over
# `application/json`. That is not what the CLI sends: it speaks Connect with
# the binary protobuf codec, over the v1 Upload and Download services, and
# verifies a commit against its b5 digest. Every one of those was broken while
# the curl suite was green (#5066), so this script pushes and resolves a
# module with `buf` itself and checks the digest it writes into buf.lock.
#
# `buf` derives its base URL as scheme plus host from the module name's first
# segment and appends the RPC path, and a module name is exactly three
# segments, so there is nowhere to put the /proto/{repo_key} prefix this
# registry serves BSR under. A reverse proxy therefore maps a host root onto
# one repository, which is also how an operator points `buf` at a hosted
# repository; this script runs a minimal one on BSR_PROXY_PORT.
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
REPO_KEY="${REPO_KEY:-test-protobuf-buf-cli}"
ADMIN_USER="${ADMIN_USER:-admin}"
BSR_PROXY_PORT="${BSR_PROXY_PORT:-18081}"
# Throwaway e2e admin credential, defined once in the repository-root
# .env.test (#3490), as in the other native tests.
_ak_test_env="$(dirname "$0")/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"

echo "==> Protobuf / BSR test with the real buf CLI"
echo "Registry: $REGISTRY_URL"
echo "Repo key: $REPO_KEY"

if ! command -v buf >/dev/null 2>&1; then
  echo "  SKIP: buf is not on PATH (install: https://buf.build/docs/installation)"
  exit 0
fi
echo "  buf: $(buf --version)"

WORK="$(mktemp -d)"
PROXY_PID=""
cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Auth + repository
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

echo "==> Creating protobuf repository..."
curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO_KEY\",\"name\":\"Protobuf buf CLI\",\"format\":\"protobuf\",\"repo_type\":\"local\",\"is_public\":true}" \
  >/dev/null 2>&1 || true
echo "  Repository ready"

# --------------------------------------------------------------------------
# The reverse proxy: host root -> /proto/{repo_key}/
# --------------------------------------------------------------------------
echo "==> Starting the BSR proxy on port $BSR_PROXY_PORT..."
cat > "$WORK/proxy.py" <<'PYEOF'
"""Maps this host's root onto one repository's BSR base path."""

import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ["UPSTREAM"].rstrip("/")
PREFIX = "/proto/" + os.environ["REPO_KEY"]
FORWARDED = ("content-type", "authorization", "connect-protocol-version", "accept-encoding")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        req = urllib.request.Request(UPSTREAM + PREFIX + self.path, data=body, method="POST")
        for name in FORWARDED:
            value = self.headers.get(name)
            if value:
                req.add_header(name, value)
        try:
            with urllib.request.urlopen(req) as resp:
                self.respond(resp.status, resp.headers.get("content-type"), resp.read())
        except urllib.error.HTTPError as e:
            # A Connect error is a status plus a JSON body the CLI reads, so it
            # has to reach the client as it stands, not as a proxy error.
            self.respond(e.code, e.headers.get("content-type"), e.read())
        except urllib.error.URLError as e:
            self.respond(502, "text/plain", str(e).encode())

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("content-type", content_type or "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PYEOF
UPSTREAM="$REGISTRY_URL" REPO_KEY="$REPO_KEY" python3 "$WORK/proxy.py" "$BSR_PROXY_PORT" &
PROXY_PID=$!
for _ in $(seq 1 20); do
  curl -s -o /dev/null --max-time 1 "http://localhost:$BSR_PROXY_PORT/" && break
  sleep 0.5
done
echo "  Proxy up (pid $PROXY_PID)"

# buf speaks https unless its own config turns TLS off, and the proxy is plain
# http here.
mkdir -p "$WORK/bufcfg"
printf 'version: v1\ntls:\n  use: false\n' > "$WORK/bufcfg/config.yaml"
export BUF_CONFIG_DIR="$WORK/bufcfg"
export BUF_TOKEN="$TOKEN"
REGISTRY="localhost:$BSR_PROXY_PORT"

# --------------------------------------------------------------------------
# Test 1: buf push
# --------------------------------------------------------------------------
echo "==> Test 1: buf push --create..."
mkdir -p "$WORK/module/acme/payments/v1"
cat > "$WORK/module/acme/payments/v1/payments.proto" <<'EOF'
syntax = "proto3";

package acme.payments.v1;

message PaymentRequest {
  string order_id = 1;
  int64 amount_cents = 2;
}
EOF
cat > "$WORK/module/buf.yaml" <<EOF
version: v2
modules:
  - path: .
    name: $REGISTRY/acme/payments
EOF
# Not `PUSH_OUT=$(buf push)`: under `set -e` a failing command substitution
# aborts the script and buf's diagnosis -- the part worth reading -- is lost.
PUSH_STATUS=0
PUSH_OUT=$( (cd "$WORK/module" && buf push --create --create-visibility public 2>&1) ) || PUSH_STATUS=$?
echo "$PUSH_OUT" | sed 's/^/    /'
COMMIT_ID=$(printf '%s' "$PUSH_OUT" | tail -n 1 | sed 's/.*://')
if [ "$PUSH_STATUS" -ne 0 ] || ! printf '%s' "$COMMIT_ID" | grep -Eq '^[0-9a-f]{32}$'; then
  echo "ERROR: buf push failed (exit $PUSH_STATUS); it reports no commit id (tuuid)"
  exit 1
fi
echo "  Pushed commit: $COMMIT_ID"

# --------------------------------------------------------------------------
# Test 2: buf dep update resolves it, and accepts its b5 digest
# --------------------------------------------------------------------------
echo "==> Test 2: buf dep update (b5 digest verification)..."
mkdir -p "$WORK/consumer/acme/orders/v1"
cat > "$WORK/consumer/buf.yaml" <<EOF
version: v2
modules:
  - path: .
deps:
  - $REGISTRY/acme/payments
EOF
cat > "$WORK/consumer/acme/orders/v1/orders.proto" <<'EOF'
syntax = "proto3";

package acme.orders.v1;

import "acme/payments/v1/payments.proto";

message Order {
  string id = 1;
  acme.payments.v1.PaymentRequest payment = 2;
}
EOF
(cd "$WORK/consumer" && buf dep update 2>&1 | sed 's/^/    /')
if ! grep -q "commit: $COMMIT_ID" "$WORK/consumer/buf.lock"; then
  echo "ERROR: buf.lock does not name the pushed commit"
  cat "$WORK/consumer/buf.lock"
  exit 1
fi
# The digest is the CLI's own: it recomputes b5 over what it downloaded and
# refuses the commit if the registry's digest disagrees, so reaching this line
# means the two agree.
if ! grep -q 'digest: b5:' "$WORK/consumer/buf.lock"; then
  echo "ERROR: buf.lock carries no b5 digest"
  cat "$WORK/consumer/buf.lock"
  exit 1
fi
echo "  buf.lock pins the commit and its b5 digest"

# --------------------------------------------------------------------------
# Test 3: the dependency actually compiles
# --------------------------------------------------------------------------
echo "==> Test 3: buf build against the fetched dependency..."
(cd "$WORK/consumer" && buf build 2>&1 | sed 's/^/    /')
echo "  Consumer builds against the downloaded module"

echo ""
echo "==> All buf CLI tests passed"
