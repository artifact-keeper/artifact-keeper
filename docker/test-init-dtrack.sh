#!/bin/bash
# Regression test for docker/init-dtrack.sh (Bug #978 + foreign-key safety
# rail #1041 follow-up).
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
#   - PUT  /api/v1/team/<uuid>/key           -> {"key":"<unmasked>","publicId":"..."}
#   - POST /api/v1/configProperty            -> 200
#
# Mock state and behavior knobs (env vars passed to mock_dtrack.py):
#   - SEED_FOREIGN_PUBLIC_ID  pre-attach a key with this publicId before
#                             startup, simulating an operator-attached
#                             integration key on the Automation team
#   - FAIL_PUT_KEY_ONCE       if "1", the first PUT /key returns 500 to
#                             exercise the script's negative path
#
# This test deliberately uses no test framework other than bash + python3 +
# curl, all of which are already required by the docker image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SCRIPT="$SCRIPT_DIR/init-dtrack.sh"

if [ ! -x "$INIT_SCRIPT" ]; then
  echo "FAIL: $INIT_SCRIPT not found or not executable" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
MOCK_PID=""
trap 'rm -rf "$WORK_DIR"; [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true' EXIT

SHARED_DIR="$WORK_DIR/shared"
mkdir -p "$SHARED_DIR"

# Pick an ephemeral port for the mock server.
MOCK_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
MOCK_URL="http://127.0.0.1:$MOCK_PORT"

# The unmasked key the mock will return from PUT /api/v1/team/<uuid>/key.
# A passing test must end up with this exact value at the API key file path.
EXPECTED_KEY="odt_TEST_FAKE_DO_NOT_USE_AUTOMATION"
MASKED_KEY="odt_********ECRET"  # what GET /team would expose (the broken path)

cat > "$WORK_DIR/mock_dtrack.py" <<PYEOF
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

EXPECTED_KEY = os.environ["EXPECTED_KEY"]
MASKED_KEY   = os.environ["MASKED_KEY"]
TEAM_UUID    = "11111111-2222-3333-4444-555555555555"

# Optional pre-seeded foreign key (an operator-attached integration key).
# Tests that exercise the refuse-to-rotate guard set this; happy-path tests
# leave it unset so the team starts empty (matches a fresh DT install).
SEED_FOREIGN = os.environ.get("SEED_FOREIGN_PUBLIC_ID", "").strip()

# Negative-path knob: if "1", the first PUT /key returns HTTP 500 so the
# init script's error branch can be exercised without random fault injection.
FAIL_PUT_KEY_ONCE = os.environ.get("FAIL_PUT_KEY_ONCE", "0") == "1"

state = {
    "keys": ([{"publicId": SEED_FOREIGN, "maskedKey": MASKED_KEY}]
             if SEED_FOREIGN else []),
    "put_key_count": 0,
    "put_key_failed_once": False,
}
KEY_LOG = os.environ["KEY_LOG"]

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
        if self.path == "/api/v1/configProperty":
            return self._send(200)
        return self._send(404)

    def do_PUT(self):
        if self.path == f"/api/v1/team/{TEAM_UUID}/key":
            # Negative-path injection: fail the first call, then recover.
            if FAIL_PUT_KEY_ONCE and not state["put_key_failed_once"]:
                state["put_key_failed_once"] = True
                return self._send(500, b'{"error":"injected failure"}')
            # DT 4.11.x: PUT returns the unmasked key once. Status pinned to
            # 201 to match the implementation contract.
            state["put_key_count"] += 1
            n = state["put_key_count"]
            unmasked = f"{EXPECTED_KEY}_run{n}"
            new = {"publicId": f"newpub{n}",
                   "maskedKey": f"odt_********KEY{n}",
                   "key": unmasked}
            state["keys"].append({"publicId": new["publicId"],
                                  "maskedKey": new["maskedKey"]})
            with open(KEY_LOG, "a") as f:
                f.write(unmasked + "\n")
            return self._send(201, json.dumps(new).encode())
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

KEY_LOG="$WORK_DIR/keys.log"
: > "$KEY_LOG"

# start_mock <var=value>... — (re)launch the mock with the given env overrides.
# Tests that need to inject foreign keys or fault-injection knobs restart
# the mock between phases; a fresh server discards the previous state.
start_mock() {
  if [ -n "$MOCK_PID" ]; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
    MOCK_PID=""
  fi
  # Use `env` rather than inline VAR=val so positional args of the form
  # KEY=val passed by callers are honored as env assignments. The shell
  # only treats inline VAR=val as an env override when it appears literally
  # at the start of a command — not when it arrives via "$@" expansion.
  env EXPECTED_KEY="$EXPECTED_KEY" MASKED_KEY="$MASKED_KEY" KEY_LOG="$KEY_LOG" \
    "$@" \
    python3 "$WORK_DIR/mock_dtrack.py" "$MOCK_PORT" >>"$WORK_DIR/mock.log" 2>&1 &
  MOCK_PID=$!
  for i in $(seq 1 50); do
    if curl -sf "$MOCK_URL/api/version" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  echo "FAIL: mock DT did not become ready" >&2
  cat "$WORK_DIR/mock.log" >&2
  exit 1
}

start_mock

# Run the init script against the mock. We rewrite the hard-coded
# /shared/dtrack-api-key path on the fly so the test doesn't need root.
SANDBOXED="$WORK_DIR/init-dtrack.sh"
sed "s|/shared/|$SHARED_DIR/|g" "$INIT_SCRIPT" > "$SANDBOXED"
chmod +x "$SANDBOXED"

run_init() {
  local out_prefix="$1"; shift
  set +e
  DEPENDENCY_TRACK_URL="$MOCK_URL" "$@" \
    "$SANDBOXED" > "$WORK_DIR/${out_prefix}.out" 2> "$WORK_DIR/${out_prefix}.err"
  local rc=$?
  set -e
  echo "$rc"
}

KEY_FILE="$SHARED_DIR/dtrack-api-key"
PUBLIC_ID_MARKER="$SHARED_DIR/.dtrack-publicid"

fail() {
  echo "FAIL: $1" >&2
  for f in init init2 init3 init4 init5 init6; do
    if [ -f "$WORK_DIR/${f}.out" ] || [ -f "$WORK_DIR/${f}.err" ]; then
      echo "--- ${f} stdout ---" >&2; cat "$WORK_DIR/${f}.out" 2>/dev/null >&2 || true
      echo "--- ${f} stderr ---" >&2; cat "$WORK_DIR/${f}.err" 2>/dev/null >&2 || true
    fi
  done
  echo "--- mock log ---"   >&2; cat "$WORK_DIR/mock.log" >&2 || true
  exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: cold start (clean DT, empty volume)
# ─────────────────────────────────────────────────────────────────────────────
INIT_RC=$(run_init init)
[ "$INIT_RC" -eq 0 ] || fail "Phase 1 cold start exited $INIT_RC (expected 0)"
[ -s "$KEY_FILE" ]    || fail "Phase 1: $KEY_FILE missing or empty"
FIRST_KEY="$(tr -d '\n' < "$KEY_FILE")"
EXPECTED_FIRST="${EXPECTED_KEY}_run1"
[ "$FIRST_KEY" = "$EXPECTED_FIRST" ] || \
  fail "Phase 1: API key file '$FIRST_KEY' != expected '$EXPECTED_FIRST'"
[ -s "$PUBLIC_ID_MARKER" ] || fail "Phase 1: $PUBLIC_ID_MARKER missing — ownership not recorded"
OUR_PUBLIC_ID="$(cat "$PUBLIC_ID_MARKER")"
[ "$OUR_PUBLIC_ID" = "newpub1" ] || \
  fail "Phase 1: publicId marker '$OUR_PUBLIC_ID' != expected 'newpub1'"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: warm restart — must short-circuit, NOT re-hit PUT /key, AND log it
# ─────────────────────────────────────────────────────────────────────────────
INIT_RC2=$(run_init init2)
[ "$INIT_RC2" -eq 0 ] || fail "Phase 2 warm restart exited $INIT_RC2 (expected 0)"
[ -s "$KEY_FILE" ]    || fail "Phase 2: $KEY_FILE missing after warm restart"

# Behavioral assertion: mock saw exactly one PUT /key total.
PUT_COUNT_AFTER_WARM=$(wc -l < "$KEY_LOG" | tr -d ' ')
[ "$PUT_COUNT_AFTER_WARM" -eq 1 ] || \
  fail "Phase 2: warm restart hit PUT /key (count=${PUT_COUNT_AFTER_WARM}, expected 1)"

# Log-content assertion: warm restart must take the explicit short-circuit
# branch (line ~54-57 of init-dtrack.sh: "API key already provisioned ...
# skipping"). Without this, a future refactor that bypasses the early-exit
# but happens to no-op the PUT elsewhere would still pass PUT_COUNT==1.
grep -q 'already provisioned' "$WORK_DIR/init2.out" || \
  fail "Phase 2: warm restart did not emit 'already provisioned' short-circuit log"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: cold-start rotation (operator deleted just the API key file)
# Marker file persists, so init recognizes its own publicId and rotates safely.
# ─────────────────────────────────────────────────────────────────────────────
rm -f "$KEY_FILE"
INIT_RC3=$(run_init init3)
[ "$INIT_RC3" -eq 0 ] || fail "Phase 3 cold-start rerun exited $INIT_RC3 (expected 0)"
[ -s "$KEY_FILE" ]    || fail "Phase 3: $KEY_FILE missing after cold-start rerun"
SECOND_KEY="$(tr -d '\n' < "$KEY_FILE")"
[ "$SECOND_KEY" != "$FIRST_KEY" ] || \
  fail "Phase 3: rotation did not fire (second key '$SECOND_KEY' equals first)"
PUT_COUNT=$(wc -l < "$KEY_LOG" | tr -d ' ')
[ "$PUT_COUNT" -ge 2 ] || \
  fail "Phase 3: expected PUT /key >=2 across runs, mock saw $PUT_COUNT"
echo "[test] rotation path fired: ${FIRST_KEY} -> ${SECOND_KEY} (PUT /key count=${PUT_COUNT})"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: foreign-key safety rail — refuse to rotate by default
# Wipe the volume to simulate fresh PVC, then pre-seed a foreign integration
# key on the team. Init must REFUSE to rotate (exit 2) and the foreign key
# must still exist on the team after the refusal.
# ─────────────────────────────────────────────────────────────────────────────
rm -f "$KEY_FILE" "$PUBLIC_ID_MARKER" "$SHARED_DIR/.dtrack-bootstrapped"
start_mock SEED_FOREIGN_PUBLIC_ID="operator-integration-key-001"

INIT_RC4=$(run_init init4)
[ "$INIT_RC4" -eq 2 ] || \
  fail "Phase 4: foreign-key present, expected refusal (exit 2), got $INIT_RC4"
[ ! -f "$KEY_FILE" ] || \
  fail "Phase 4: refusal still wrote $KEY_FILE — partial provisioning leaked"
grep -q 'refusing to rotate' "$WORK_DIR/init4.err" || \
  fail "Phase 4: refusal did not emit 'refusing to rotate' diagnostic"
grep -q 'operator-integration-key-001' "$WORK_DIR/init4.err" || \
  fail "Phase 4: refusal did not name the foreign publicId in stderr"

# Verify the foreign key was NOT deleted from the team.
TEAM_AFTER=$(curl -sf "$MOCK_URL/api/v1/team")
echo "$TEAM_AFTER" | jq -e '.[] | select(.name=="Automation") | .apiKeys[] | select(.publicId=="operator-integration-key-001")' >/dev/null || \
  fail "Phase 4: foreign key was silently revoked despite refusal"

# ─────────────────────────────────────────────────────────────────────────────
# Phase 5: foreign-key override path — DTRACK_INIT_FORCE_ROTATE=true
# Same setup as Phase 4 but operator explicitly acknowledges revocation.
# Init must succeed, the foreign key must be deleted, and a WARNING must
# name the revoked publicId so the rotation is auditable.
# ─────────────────────────────────────────────────────────────────────────────
PUT_COUNT_BEFORE_FORCE=$(wc -l < "$KEY_LOG" | tr -d ' ')
INIT_RC5=$(run_init init5 env DTRACK_INIT_FORCE_ROTATE=true)
[ "$INIT_RC5" -eq 0 ] || \
  fail "Phase 5: FORCE_ROTATE=true expected to succeed, got $INIT_RC5"
[ -s "$KEY_FILE" ]    || fail "Phase 5: $KEY_FILE missing after forced rotate"
grep -q 'DTRACK_INIT_FORCE_ROTATE=true' "$WORK_DIR/init5.err" || \
  fail "Phase 5: forced rotation did not emit acknowledgment WARNING"
grep -q 'operator-integration-key-001' "$WORK_DIR/init5.err" || \
  fail "Phase 5: forced rotation did not name the revoked foreign publicId"

# Mint count must advance by exactly 1 — a future bug that double-mints
# under FORCE_ROTATE (e.g. retry-on-error that doesn't check the prior
# attempt) would leak an extra orphaned key. KEY_LOG is mock-side and
# survives the restart in start_mock (append-mode).
PUT_COUNT_AFTER_FORCE=$(wc -l < "$KEY_LOG" | tr -d ' ')
DELTA=$((PUT_COUNT_AFTER_FORCE - PUT_COUNT_BEFORE_FORCE))
[ "$DELTA" -eq 1 ] || \
  fail "Phase 5: FORCE_ROTATE minted $DELTA keys (expected exactly 1)"

# Foreign key must be gone now.
TEAM_AFTER_FORCE=$(curl -sf "$MOCK_URL/api/v1/team")
if echo "$TEAM_AFTER_FORCE" | jq -e '.[] | select(.name=="Automation") | .apiKeys[] | select(.publicId=="operator-integration-key-001")' >/dev/null; then
  fail "Phase 5: foreign key persisted after FORCE_ROTATE — revocation did not fire"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6: negative path — PUT /key returns 500
# Wipe state, restart mock with fault injection, init must fail loudly and
# leave no half-written API key file behind.
# ─────────────────────────────────────────────────────────────────────────────
rm -f "$KEY_FILE" "$PUBLIC_ID_MARKER" "$SHARED_DIR/.dtrack-bootstrapped"
: > "$KEY_LOG"
start_mock FAIL_PUT_KEY_ONCE=1

INIT_RC6=$(run_init init6)
[ "$INIT_RC6" -ne 0 ] || \
  fail "Phase 6: PUT /key 500 should fail init, got exit 0"
[ ! -f "$KEY_FILE" ] || \
  fail "Phase 6: failed init left a half-written $KEY_FILE on disk"
[ ! -f "$KEY_FILE.tmp" ] || \
  fail "Phase 6: failed init left a stale $KEY_FILE.tmp on disk"

echo "PASS: init-dtrack.sh — bug #978 + foreign-key safety rail (#1041 follow-up)"
