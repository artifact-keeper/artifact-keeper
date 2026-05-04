#!/bin/bash
# Regression test for docker/init-dtrack.sh (Bug #978).
#
# Spins up a tiny Python mock of Dependency-Track 4.x that mimics the
# documented behavior:
#   - GET  /api/version                      -> {version}
#   - POST /api/v1/user/forceChangePassword  -> 200
#   - POST /api/v1/user/login                -> Bearer JWT (string body)
#   - GET  /api/v1/team                      -> existing teams; the Automation
#                                               team's apiKeys ONLY expose
#                                               .maskedKey (NOT .key)  <-- the bug
#   - DELETE /api/v1/team/<uuid>/key/<pubid> -> 204 (idempotent rotation)
#   - POST /api/v1/team/<uuid>/key           -> {"key":"<unmasked>","publicId":"..."}
#   - POST /api/v1/configProperty            -> 200
#
# The test then runs init-dtrack.sh against the mock and asserts that:
#   1. The script exits with status 0.
#   2. /shared/dtrack-api-key (redirected via env) is non-empty.
#   3. The contents match the unmasked key returned by POST /key
#      (NOT the maskedKey returned by GET /team).
#
# This test deliberately uses no test framework other than bash + python3 +
# curl, all of which are already required by the docker image.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SCRIPT="$SCRIPT_DIR/init-dtrack.sh"

if [ ! -x "$INIT_SCRIPT" ]; then
  echo "FAIL: $INIT_SCRIPT not found or not executable" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true' EXIT

SHARED_DIR="$WORK_DIR/shared"
mkdir -p "$SHARED_DIR"

# Pick an ephemeral port for the mock server.
MOCK_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
MOCK_URL="http://127.0.0.1:$MOCK_PORT"

# The unmasked key the mock will return from POST /api/v1/team/<uuid>/key.
# A passing test must end up with this exact value at the API key file path.
EXPECTED_KEY="odt_NEWLY_CREATED_AUTOMATION_KEY_XYZ"
MASKED_KEY="odt_********ECRET"  # what GET /team would expose (the broken path)

cat > "$WORK_DIR/mock_dtrack.py" <<PYEOF
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

EXPECTED_KEY = os.environ["EXPECTED_KEY"]
MASKED_KEY   = os.environ["MASKED_KEY"]
TEAM_UUID    = "11111111-2222-3333-4444-555555555555"
EXISTING_PUBLIC_ID = "abc123"

# Track which key public_ids currently exist on the team. Starts with the
# pre-provisioned masked one; deletes remove it; create-key adds new ones.
state = {"keys": [{"publicId": EXISTING_PUBLIC_ID, "maskedKey": MASKED_KEY}]}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass  # quiet

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        if self.path == "/api/version":
            return self._send(200, b'{"version":"4.11.0"}')
        if self.path == "/api/v1/team":
            teams = [{
                "uuid": TEAM_UUID,
                "name": "Automation",
                # DT 4.x: existing keys only expose maskedKey, not key
                "apiKeys": [{"publicId": k["publicId"],
                             "maskedKey": k["maskedKey"]} for k in state["keys"]],
            }]
            return self._send(200, json.dumps(teams).encode())
        return self._send(404)

    def do_POST(self):
        body = self._read_body()
        if self.path == "/api/v1/user/forceChangePassword":
            return self._send(200)
        if self.path == "/api/v1/user/login":
            # DT login returns a bare JWT string, not JSON.
            return self._send(200, b"eyJhbGciOiJIUzI1NiJ9.mockjwt.signature",
                              ctype="text/plain")
        if self.path == f"/api/v1/team/{TEAM_UUID}/key":
            # DT 4.x: POST returns the unmasked key once.
            new = {"publicId": "newpub42",
                   "maskedKey": "odt_********KEY42",
                   "key": EXPECTED_KEY}
            state["keys"].append({"publicId": new["publicId"],
                                  "maskedKey": new["maskedKey"]})
            return self._send(201, json.dumps(new).encode())
        if self.path == "/api/v1/configProperty":
            return self._send(200)
        return self._send(404)

    def do_DELETE(self):
        # DELETE /api/v1/team/<uuid>/key/<publicId>  -> 204
        prefix = f"/api/v1/team/{TEAM_UUID}/key/"
        if self.path.startswith(prefix):
            pid = self.path[len(prefix):]
            state["keys"] = [k for k in state["keys"] if k["publicId"] != pid]
            return self._send(204)
        return self._send(404)

port = int(sys.argv[1])
HTTPServer(("127.0.0.1", port), H).serve_forever()
PYEOF

EXPECTED_KEY="$EXPECTED_KEY" MASKED_KEY="$MASKED_KEY" \
  python3 "$WORK_DIR/mock_dtrack.py" "$MOCK_PORT" >"$WORK_DIR/mock.log" 2>&1 &
MOCK_PID=$!

# Wait for mock to be ready.
for i in $(seq 1 50); do
  if curl -sf "$MOCK_URL/api/version" >/dev/null 2>&1; then break; fi
  sleep 0.1
  if [ "$i" -eq 50 ]; then
    echo "FAIL: mock DT did not become ready" >&2
    cat "$WORK_DIR/mock.log" >&2
    exit 1
  fi
done

# Run the init script against the mock. We rewrite the hard-coded
# /shared/dtrack-api-key path on the fly so the test doesn't need root.
SANDBOXED="$WORK_DIR/init-dtrack.sh"
sed "s|/shared/|$SHARED_DIR/|g" "$INIT_SCRIPT" > "$SANDBOXED"
chmod +x "$SANDBOXED"

set +e
DEPENDENCY_TRACK_URL="$MOCK_URL" \
  "$SANDBOXED" > "$WORK_DIR/init.out" 2> "$WORK_DIR/init.err"
INIT_RC=$?
set -e

KEY_FILE="$SHARED_DIR/dtrack-api-key"

fail() {
  echo "FAIL: $1" >&2
  echo "--- init stdout ---" >&2; cat "$WORK_DIR/init.out" >&2 || true
  echo "--- init stderr ---" >&2; cat "$WORK_DIR/init.err" >&2 || true
  echo "--- mock log ---"   >&2; cat "$WORK_DIR/mock.log" >&2 || true
  exit 1
}

# Assertion 1: exit 0
[ "$INIT_RC" -eq 0 ] || fail "init-dtrack.sh exited $INIT_RC (expected 0)"

# Assertion 2: API key file exists and is non-empty
[ -s "$KEY_FILE" ] || fail "$KEY_FILE missing or empty"

# Assertion 3: contents are the unmasked key (not the masked one).
GOT="$(tr -d '\n' < "$KEY_FILE")"
[ "$GOT" = "$EXPECTED_KEY" ] || \
  fail "API key file contents '$GOT' != expected '$EXPECTED_KEY'"

# Assertion 4: Idempotence — re-running the script must not error and must
# leave a usable key file in place. (Existing-file short-circuit is fine.)
set +e
DEPENDENCY_TRACK_URL="$MOCK_URL" \
  "$SANDBOXED" > "$WORK_DIR/init2.out" 2> "$WORK_DIR/init2.err"
INIT_RC2=$?
set -e
[ "$INIT_RC2" -eq 0 ] || fail "second run exited $INIT_RC2 (expected 0)"
[ -s "$KEY_FILE" ]    || fail "$KEY_FILE missing after second run"

echo "PASS: init-dtrack.sh writes unmasked Automation API key from POST /key"
