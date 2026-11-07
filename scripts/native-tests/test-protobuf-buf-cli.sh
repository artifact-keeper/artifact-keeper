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
# A module, a module that depends on it, and a consumer of that one. The
# chain is the point: a dependency is recorded as a commit id, and resolving
# the consumer's dependency walks the graph through the middle module, which
# a single module with no dependencies never exercises.
# --------------------------------------------------------------------------
write_module() {          # write_module <dir> <owner/module> <package> [dep]
  local dir="$1" name="$2" pkg="$3" dep="${4:-}"
  mkdir -p "$dir/$pkg"
  {
    echo "version: v2"
    echo "modules:"
    echo "  - path: ."
    echo "    name: $REGISTRY/$name"
    if [ -n "$dep" ]; then
      echo "deps:"
      echo "  - $REGISTRY/$dep"
    fi
  } > "$dir/buf.yaml"
}

push_module() {           # push_module <dir> <what> -> commit id on stdout
  local dir="$1" what="$2" status=0 out=""
  # Not `out=$(buf push)`: under `set -e` a failing command substitution
  # aborts the script and buf's diagnosis -- the part worth reading -- is
  # lost.
  out=$( (cd "$dir" && buf push --create --create-visibility public 2>&1) ) || status=$?
  echo "$out" | sed 's/^/    /' >&2
  local commit
  commit=$(printf '%s' "$out" | tail -n 1 | sed 's/.*://')
  if [ "$status" -ne 0 ] || ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{32}$'; then
    echo "ERROR: buf push of $what failed (exit $status); it reports no commit id (tuuid)" >&2
    exit 1
  fi
  printf '%s' "$commit"
}

echo "==> Test 1: buf push --create (a module with no dependencies)..."
write_module "$WORK/payments" acme/payments acme/payments/v1
cat > "$WORK/payments/acme/payments/v1/payments.proto" <<'EOF'
syntax = "proto3";

package acme.payments.v1;

message PaymentRequest {
  string order_id = 1;
  int64 amount_cents = 2;
}
EOF
PAYMENTS_COMMIT=$(push_module "$WORK/payments" acme/payments)
echo "  Pushed acme/payments: $PAYMENTS_COMMIT"

echo "==> Test 2: buf dep update + push of a module that depends on it..."
write_module "$WORK/orders" acme/orders acme/orders/v1 acme/payments
cat > "$WORK/orders/acme/orders/v1/orders.proto" <<'EOF'
syntax = "proto3";

package acme.orders.v1;

import "acme/payments/v1/payments.proto";

message Order {
  string id = 1;
  acme.payments.v1.PaymentRequest payment = 2;
}
EOF
(cd "$WORK/orders" && buf dep update 2>&1 | sed 's/^/    /')
if ! grep -q "commit: $PAYMENTS_COMMIT" "$WORK/orders/buf.lock"; then
  echo "ERROR: acme/orders did not pin the commit acme/payments was pushed as"
  cat "$WORK/orders/buf.lock"
  exit 1
fi
ORDERS_COMMIT=$(push_module "$WORK/orders" acme/orders)
echo "  Pushed acme/orders: $ORDERS_COMMIT (dependency recorded as a commit id)"

echo "==> Test 3: a consumer resolves the chain (b5 digest verification)..."
mkdir -p "$WORK/consumer/acme/checkout/v1"
cat > "$WORK/consumer/buf.yaml" <<EOF
version: v2
modules:
  - path: .
deps:
  - $REGISTRY/acme/orders
EOF
cat > "$WORK/consumer/acme/checkout/v1/checkout.proto" <<'EOF'
syntax = "proto3";

package acme.checkout.v1;

import "acme/orders/v1/orders.proto";

message Checkout {
  acme.orders.v1.Order order = 1;
}
EOF
(cd "$WORK/consumer" && buf dep update 2>&1 | sed 's/^/    /')
# Both the declared dependency and the one it brings in: resolving the chain
# walks GetGraph, where a dependency recorded as a commit id has to resolve.
for expected in "$ORDERS_COMMIT" "$PAYMENTS_COMMIT"; do
  if ! grep -q "commit: $expected" "$WORK/consumer/buf.lock"; then
    echo "ERROR: the consumer's buf.lock is missing commit $expected"
    cat "$WORK/consumer/buf.lock"
    exit 1
  fi
done
# The digests are the CLI's own: it recomputes b5 over what it downloaded and
# refuses a commit if the registry's digest disagrees, so reaching this line
# means the two agree -- for both modules in the chain.
if [ "$(grep -c 'digest: b5:' "$WORK/consumer/buf.lock")" -ne 2 ]; then
  echo "ERROR: expected a b5 digest for each module in the chain"
  cat "$WORK/consumer/buf.lock"
  exit 1
fi
echo "  buf.lock pins both commits of the chain and their b5 digests"

echo "==> Test 4: buf build against the fetched dependencies..."
(cd "$WORK/consumer" && buf build 2>&1 | sed 's/^/    /')
echo "  Consumer builds against the downloaded modules"

echo ""
echo "==> All buf CLI tests passed"
