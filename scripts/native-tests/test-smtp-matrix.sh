#!/usr/bin/env bash
# SMTP delivery regression matrix (discussion #4244, "SMTP + Exchange").
#
# Starts a set of real SMTP servers in containers, then for every cell of
#
#   SMTP_TLS_MODE  x  {auth, no auth}  x  server shape
#
# boots Artifact Keeper with that SMTP configuration, calls
# POST /api/v1/admin/smtp/test, and asserts the outcome: either the message
# arrived (checked through Mailpit's API) or the endpoint failed with the
# expected error class. One PASS/FAIL line per cell.
#
# Server shapes:
#   mailpit-tls       Mailpit, implicit TLS only (SMTPS), AUTH required
#   mailpit-starttls  Mailpit, STARTTLS required, AUTH required
#   mailpit-plain     Mailpit, plaintext, AUTH PLAIN/LOGIN allowed in clear
#   exchange          aiosmtpd, Exchange Client Frontend shape: plaintext EHLO
#                     offers only AUTH NTLM GSSAPI, LOGIN/PLAIN after STARTTLS,
#                     unauthenticated MAIL gets 530 5.7.1
#   nostarttls        aiosmtpd, Exchange connector with TLS off: no STARTTLS,
#                     AUTH NTLM GSSAPI only, anonymous relay allowed
#   privateca         aiosmtpd, STARTTLS with a certificate from a CA the
#                     backend does not trust
#
# The Mailpit and "exchange" certificates come from a test CA that the backend
# is told to trust through SSL_CERT_FILE, standing in for a public CA. The
# "privateca" certificate comes from a second CA that is only trusted when a
# cell says so. Targeted cells after the main grid:
#   badauth         wrong password against "exchange" (535 5.7.3)
#   ca / ca-inline  SMTP_TLS_CA_CERT as a path / as PEM text
#   customca        CUSTOM_CA_CERT_PATH only
#   ca-over-custom  SMTP_TLS_CA_CERT wins over a wrong CUSTOM_CA_CERT_PATH
#   wrongca         SMTP_TLS_CA_CERT set to an unrelated CA (still fails)
#   skipverify      SMTP_TLS_SKIP_VERIFY=true
#   sslcertfile     no SMTP setting; OpenSSL's SSL_CERT_FILE holds the CA
#   systemstore     (AK_IMAGE only) the CA appended to the image's system bundle
#
# A full run is about 60 cells and takes roughly 15 minutes: the cells that
# talk plaintext to the implicit-TLS port wait out the backend's 60s send
# timeout. SMTP_MATRIX_ONLY narrows it.
#
# Usage:
#   AK_BIN=target/release/artifact-keeper ./scripts/native-tests/test-smtp-matrix.sh
#   AK_IMAGE=ghcr.io/artifact-keeper/artifact-keeper-backend:dev ./scripts/native-tests/test-smtp-matrix.sh
#
#   ./test-smtp-matrix.sh up      start the SMTP servers (and Postgres) and leave them running
#   ./test-smtp-matrix.sh run     run the matrix (default; starts servers if needed, stops them after)
#   ./test-smtp-matrix.sh cell SERVER MODE AUTH [EXTRA]
#                                 run one cell and print the response and log line
#   ./test-smtp-matrix.sh down    remove every container this script created
#
# Environment:
#   AK_BIN / AK_IMAGE   backend to test (one is required; the test is skipped
#                       when neither is set, or when no container runtime exists)
#   DATABASE_URL        Postgres for the backend; when unset the script starts
#                       aksmtp-matrix-pg on 127.0.0.1:$PG_PORT
#   SMTP_MATRIX_PROFILE "current" (default) or "baseline". Baseline drops the
#                       starttls-opportunistic mode and the CA / skip-verify
#                       cells, for backends that predate them.
#   SMTP_MATRIX_ONLY    optional grep -E filter on cell ids
#   CONTAINER_RT        podman or docker (auto-detected)
#   REQUIRE_SMTP_MATRIX=1  fail instead of skipping when prerequisites are missing
#
# Requires: bash, curl, jq, openssl, podman or docker.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/smtp"

_ak_test_env="$SCRIPT_DIR/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"

PREFIX="aksmtp-matrix"
NET="$PREFIX-net"
MAILPIT_IMAGE="${MAILPIT_IMAGE:-docker.io/axllent/mailpit:v1.31.4}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/library/python:3.13-slim}"
AIOSMTPD_VERSION="${AIOSMTPD_VERSION:-1.4.6}"
PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:18-alpine}"

PORT_BASE="${SMTP_MATRIX_PORT_BASE:-54400}"
P_MP_TLS=$((PORT_BASE + 1))
P_MP_STARTTLS=$((PORT_BASE + 2))
P_MP_PLAIN=$((PORT_BASE + 3))
P_EXCHANGE=$((PORT_BASE + 4))
P_NOSTARTTLS=$((PORT_BASE + 5))
P_PRIVATECA=$((PORT_BASE + 6))
API_MP_TLS=$((PORT_BASE + 11))
API_MP_STARTTLS=$((PORT_BASE + 12))
API_MP_PLAIN=$((PORT_BASE + 13))
API_SINK=$((PORT_BASE + 14))
PG_PORT=$((PORT_BASE + 20))
AK_PORT="${AK_PORT:-$((PORT_BASE + 80))}"
AK_URL="http://127.0.0.1:$AK_PORT"

SMTP_USER="ak-matrix"
STATE_DIR="${SMTP_MATRIX_STATE_DIR:-${TMPDIR:-/tmp}/aksmtp-matrix}"
TLS_DIR="$STATE_DIR/tls"
PROFILE="${SMTP_MATRIX_PROFILE:-current}"
CELL_TIMEOUT="${SMTP_MATRIX_CELL_TIMEOUT:-150}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0
FAILED_CELLS=()

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAILED=$((FAILED + 1)); FAILED_CELLS+=("$1"); }
skip_all() {
    echo -e "  ${YELLOW}SKIP${NC}: $1"
    if [ "${REQUIRE_SMTP_MATRIX:-0}" = "1" ]; then exit 1; fi
    exit 0
}

# ---------------------------------------------------------------------------
# prerequisites
# ---------------------------------------------------------------------------
detect_runtime() {
    if [ -n "${CONTAINER_RT:-}" ]; then return; fi
    if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        CONTAINER_RT=podman
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_RT=docker
    else
        CONTAINER_RT=""
    fi
}

check_prereqs() {
    detect_runtime
    [ -n "$CONTAINER_RT" ] || skip_all "no usable podman or docker"
    for c in curl jq openssl; do
        command -v "$c" >/dev/null 2>&1 || skip_all "required command not found: $c"
    done
}

check_backend() {
    if [ -z "${AK_BIN:-}" ] && [ -z "${AK_IMAGE:-}" ]; then
        skip_all "set AK_BIN (backend binary) or AK_IMAGE (backend image)"
    fi
    if [ -n "${AK_BIN:-}" ] && [ ! -x "$AK_BIN" ]; then
        skip_all "AK_BIN is not executable: $AK_BIN"
    fi
    [ -n "$ADMIN_PASS" ] || skip_all "no admin password (ADMIN_PASS or .env.test)"
}

rt() { "$CONTAINER_RT" "$@"; }

# ---------------------------------------------------------------------------
# certificates and credentials
# ---------------------------------------------------------------------------
make_ca() {
    local name="$1" cn="$2"
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
        -subj "/CN=$cn" -keyout "$TLS_DIR/$name-ca.key" -out "$TLS_DIR/$name-ca.pem" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}

make_leaf() {
    local ca="$1" name="$2"
    openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=localhost" \
        -keyout "$TLS_DIR/$name.key" -out "$TLS_DIR/$name.csr" >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
        > "$TLS_DIR/$name.ext"
    openssl x509 -req -in "$TLS_DIR/$name.csr" -CA "$TLS_DIR/$ca-ca.pem" \
        -CAkey "$TLS_DIR/$ca-ca.key" -CAcreateserial -days 30 -sha256 \
        -extfile "$TLS_DIR/$name.ext" -out "$TLS_DIR/$name.pem" >/dev/null 2>&1
}

prepare_state() {
    mkdir -p "$TLS_DIR"
    chmod 700 "$STATE_DIR"
    if [ ! -s "$TLS_DIR/server.pem" ]; then
        make_ca public "aksmtp matrix stand-in public CA"
        make_ca private "aksmtp matrix private CA"
        make_leaf public server
        make_leaf private privateca-server
    fi
    cat "$TLS_DIR/public-ca.pem" "$TLS_DIR/private-ca.pem" > "$TLS_DIR/both-ca.pem"
    chmod 644 "$TLS_DIR"/*.pem "$TLS_DIR"/*.key
    chmod 755 "$TLS_DIR"
    if [ ! -s "$STATE_DIR/smtp-pass" ]; then
        openssl rand -hex 12 > "$STATE_DIR/smtp-pass"
    fi
    SMTP_PASS="$(cat "$STATE_DIR/smtp-pass")"
    printf '%s:%s\n' "$SMTP_USER" "$SMTP_PASS" > "$STATE_DIR/mailpit-auth"
    chmod 644 "$STATE_DIR/mailpit-auth"
    if [ -z "${DATABASE_URL:-}" ]; then
        if [ ! -s "$STATE_DIR/pg-pass" ]; then
            openssl rand -hex 16 > "$STATE_DIR/pg-pass"
        fi
        DATABASE_URL="postgres://registry:$(cat "$STATE_DIR/pg-pass")@127.0.0.1:$PG_PORT/artifact_registry"
        OWN_PG=1
    else
        OWN_PG=0
    fi
}

# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------
running() { [ "$(rt inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

start_mailpit() {
    local name="$1" smtp_port="$2" api_port="$3"
    shift 3
    running "$PREFIX-$name" && return 0
    rt rm -f "$PREFIX-$name" >/dev/null 2>&1
    local publish=(-p "127.0.0.1:$api_port:8025")
    [ "$smtp_port" != "-" ] && publish+=(-p "127.0.0.1:$smtp_port:1025")
    rt run -d --name "$PREFIX-$name" --network "$NET" --network-alias "$name" \
        "${publish[@]}" -v "$STATE_DIR:/state:ro,z" \
        "$MAILPIT_IMAGE" --smtp-disable-rdns "$@" >/dev/null
}

start_aiosmtpd() {
    local shape="$1" port="$2" cert="$3"
    running "$PREFIX-$shape" && return 0
    rt rm -f "$PREFIX-$shape" >/dev/null 2>&1
    rt run -d --name "$PREFIX-$shape" --network "$NET" \
        -p "127.0.0.1:$port:2525" \
        -v "$STATE_DIR:/state:ro,z" -v "$FIXTURE_DIR:/fixture:ro,z" \
        -e SHAPE="$shape" -e PORT=2525 \
        -e TLS_CERT="/state/tls/$cert.pem" -e TLS_KEY="/state/tls/$cert.key" \
        -e AUTH_USER="$SMTP_USER" -e AUTH_PASS="$SMTP_PASS" \
        -e RELAY_HOST=sink -e RELAY_PORT=1025 \
        "$PYTHON_IMAGE" sh -c \
        "pip install -q --disable-pip-version-check --root-user-action=ignore aiosmtpd==$AIOSMTPD_VERSION \
         && exec python -u /fixture/exchange_like_smtpd.py" >/dev/null
}

start_postgres() {
    [ "$OWN_PG" = "1" ] || return 0
    running "$PREFIX-pg" && return 0
    rt rm -f "$PREFIX-pg" >/dev/null 2>&1
    rt run -d --name "$PREFIX-pg" -p "127.0.0.1:$PG_PORT:5432" \
        -e POSTGRES_USER=registry -e POSTGRES_PASSWORD="$(cat "$STATE_DIR/pg-pass")" \
        -e POSTGRES_DB=artifact_registry "$PG_IMAGE" postgres >/dev/null
    for _ in $(seq 1 60); do
        rt exec "$PREFIX-pg" pg_isready -U registry >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "ERROR: Postgres did not become ready"
    exit 1
}

# Wait for a server's own "listening" log line. A TCP probe is not enough:
# rootless port forwarders accept connections before the process listens.
wait_ready() {
    local what="$1" pattern="$2"
    for _ in $(seq 1 120); do
        # Capture first: grep -q closing the pipe early would trip pipefail.
        local logs
        logs="$(rt logs "$PREFIX-$what" 2>&1)"
        if grep -q "$pattern" <<<"$logs"; then return 0; fi
        running "$PREFIX-$what" || break
        sleep 1
    done
    echo "ERROR: $what did not become ready"
    rt logs "$PREFIX-$what" 2>&1 | tail -20
    exit 1
}

servers_up() {
    rt network exists "$NET" >/dev/null 2>&1 || rt network inspect "$NET" >/dev/null 2>&1 \
        || rt network create "$NET" >/dev/null
    start_postgres
    local mp_auth=(--smtp-auth-file /state/mailpit-auth)
    local mp_tls=(--smtp-tls-cert /state/tls/server.pem --smtp-tls-key /state/tls/server.key)
    start_mailpit mailpit-tls "$P_MP_TLS" "$API_MP_TLS" "${mp_auth[@]}" "${mp_tls[@]}" --smtp-require-tls
    start_mailpit mailpit-starttls "$P_MP_STARTTLS" "$API_MP_STARTTLS" "${mp_auth[@]}" "${mp_tls[@]}" --smtp-require-starttls
    start_mailpit mailpit-plain "$P_MP_PLAIN" "$API_MP_PLAIN" "${mp_auth[@]}" --smtp-auth-allow-insecure
    start_mailpit sink - "$API_SINK" --smtp-auth-accept-any --smtp-auth-allow-insecure
    start_aiosmtpd exchange "$P_EXCHANGE" server
    start_aiosmtpd nostarttls "$P_NOSTARTTLS" server
    start_aiosmtpd privateca "$P_PRIVATECA" privateca-server
    for m in mailpit-tls mailpit-starttls mailpit-plain sink; do
        wait_ready "$m" '\[smtpd\] starting'
    done
    for a in exchange nostarttls privateca; do
        wait_ready "$a" 'listening on'
    done
}

servers_down() {
    detect_runtime
    [ -n "$CONTAINER_RT" ] || return 0
    local names
    names="$(rt ps -a --format '{{.Names}}' | grep "^$PREFIX-" || true)"
    # shellcheck disable=SC2086
    [ -n "$names" ] && rt rm -f $names >/dev/null 2>&1
    rt network rm "$NET" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# backend
# ---------------------------------------------------------------------------
BACKEND_PID=""
BACKEND_LOG=""
CUR_EXTRA=""
CELL_BODY=""
CELL_LOG=""

backend_env() {
    # $1 server, $2 mode, $3 auth (auth|noauth|badauth), $4 extra (""|ca|ca-inline|skipverify)
    local server="$1" mode="$2" auth="$3" extra="${4:-}" port
    case "$server" in
        mailpit-tls) port=$P_MP_TLS ;;
        mailpit-starttls) port=$P_MP_STARTTLS ;;
        mailpit-plain) port=$P_MP_PLAIN ;;
        exchange) port=$P_EXCHANGE ;;
        nostarttls) port=$P_NOSTARTTLS ;;
        privateca) port=$P_PRIVATECA ;;
        *) echo "unknown server $server" >&2; return 1 ;;
    esac
    # An image runs as its own non-root user, which cannot write a bind
    # mount under rootless podman: keep its data inside the container and
    # mount only the certificates (read-only, same path).
    local data="$STATE_DIR"
    [ -n "${AK_IMAGE:-}" ] && [ -z "${AK_BIN:-}" ] && data="/tmp/aksmtp"
    BENV=(
        "DATABASE_URL=$DATABASE_URL"
        "JWT_SECRET=aksmtp-matrix-jwt-secret-with-enough-entropy-0123456789"
        "ADMIN_PASSWORD=$ADMIN_PASS"
        "BIND_ADDRESS=127.0.0.1:$AK_PORT"
        "GRPC_PORT=$((AK_PORT + 1))"
        "METRICS_PORT=$((AK_PORT + 2))"
        "STORAGE_PATH=$data/storage"
        "SCAN_WORKSPACE_PATH=$data/scan"
        "BACKUP_PATH=$data/backups"
        "PLUGINS_DIR=$data/plugins"
        "RATE_LIMIT_ENABLED=false"
        "RUST_LOG=${RUST_LOG:-info}"
        "SMTP_HOST=localhost"
        "SMTP_PORT=$port"
        "SMTP_FROM_ADDRESS=ak-matrix@example.test"
        "SMTP_TLS_MODE=$mode"
    )
    CUR_EXTRA="$extra"
    case "$extra" in
        sslcertfile) BENV+=("SSL_CERT_FILE=$TLS_DIR/both-ca.pem") ;;
        systemstore) ;;
        *) BENV+=("SSL_CERT_FILE=$TLS_DIR/public-ca.pem") ;;
    esac
    case "$auth" in
        auth) BENV+=("SMTP_USERNAME=$SMTP_USER" "SMTP_PASSWORD=$SMTP_PASS") ;;
        badauth) BENV+=("SMTP_USERNAME=$SMTP_USER" "SMTP_PASSWORD=wrong-$SMTP_PASS") ;;
        noauth) ;;
    esac
    case "$extra" in
        ca) BENV+=("SMTP_TLS_CA_CERT=$TLS_DIR/private-ca.pem") ;;
        ca-inline) BENV+=("SMTP_TLS_CA_CERT=$(cat "$TLS_DIR/private-ca.pem")") ;;
        customca) BENV+=("CUSTOM_CA_CERT_PATH=$TLS_DIR/private-ca.pem") ;;
        # SMTP_TLS_CA_CERT overrides CUSTOM_CA_CERT_PATH (here a wrong CA).
        ca-over-custom) BENV+=("CUSTOM_CA_CERT_PATH=$TLS_DIR/public-ca.pem"
                               "SMTP_TLS_CA_CERT=$TLS_DIR/private-ca.pem") ;;
        wrongca) BENV+=("SMTP_TLS_CA_CERT=$TLS_DIR/public-ca.pem") ;;
        # Zero-config path: OpenSSL (native-tls) reads SSL_CERT_FILE, here a
        # bundle that also holds the private CA.
        sslcertfile) ;;
        # Image only: the private CA appended to the image's system bundle
        # (what update-ca-trust would produce), no SSL_CERT_FILE.
        systemstore) ;;
        skipverify) BENV+=("SMTP_TLS_SKIP_VERIFY=true") ;;
        "") ;;
    esac
}

start_backend() {
    mkdir -p "$STATE_DIR/storage" "$STATE_DIR/scan" "$STATE_DIR/backups" "$STATE_DIR/plugins"
    BACKEND_LOG="$STATE_DIR/backend.log"
    : > "$BACKEND_LOG"
    if [ -n "${AK_BIN:-}" ]; then
        env -i "PATH=$PATH" "HOME=${HOME:-/tmp}" "${BENV[@]}" "$AK_BIN" >"$BACKEND_LOG" 2>&1 &
        BACKEND_PID=$!
    else
        local args=()
        for kv in "${BENV[@]}"; do args+=(-e "$kv"); done
        if [ "$CUR_EXTRA" = systemstore ]; then
            local sys=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
            rt run --rm --entrypoint "" "$AK_IMAGE" cat "$sys" > "$TLS_DIR/system-plus-private.pem" 2>/dev/null
            cat "$TLS_DIR/private-ca.pem" >> "$TLS_DIR/system-plus-private.pem"
            args+=(-v "$TLS_DIR/system-plus-private.pem:$sys:ro,z")
        fi
        rt rm -f "$PREFIX-ak" >/dev/null 2>&1
        rt run -d --name "$PREFIX-ak" --network host -v "$TLS_DIR:$TLS_DIR:ro,z" \
            "${args[@]}" "$AK_IMAGE" >/dev/null
    fi
    for _ in $(seq 1 180); do
        if curl -fsS -o /dev/null --max-time 2 "$AK_URL/health" 2>/dev/null; then return 0; fi
        if [ -n "$BACKEND_PID" ] && ! kill -0 "$BACKEND_PID" 2>/dev/null; then break; fi
        sleep 1
    done
    echo "ERROR: backend did not become healthy"
    backend_logs | tail -30
    stop_backend
    return 1
}

backend_logs() {
    if [ -n "${AK_BIN:-}" ]; then cat "$BACKEND_LOG"; else rt logs "$PREFIX-ak" 2>&1; fi
}

stop_backend() {
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null
        wait "$BACKEND_PID" 2>/dev/null
        BACKEND_PID=""
    elif [ -n "${AK_IMAGE:-}" ]; then
        rt logs "$PREFIX-ak" >"$BACKEND_LOG" 2>&1
        rt rm -f "$PREFIX-ak" >/dev/null 2>&1
    fi
}

login() {
    curl -sS --max-time 20 -X POST "$AK_URL/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d "$(jq -cn --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" \
        | jq -r '.access_token // empty'
}

# ---------------------------------------------------------------------------
# one cell
# ---------------------------------------------------------------------------
# Error classes, matched against the smtp/test response message.
classify() {
    local code="$1" body="$2"
    if [ "$code" = "200" ]; then echo delivered-ish; return; fi
    case "$body" in
        *"No compatible authentication mechanism"*) echo no-mechanism ;;
        *"STARTTLS is not supported"*) echo no-starttls ;;
        *"(535)"*) echo auth-rejected ;;
        *"(530)"*) echo auth-required ;;
        # lettre reports TLS failures as "Connection error: ... SSL routines ...".
        *"tls error"*|*"certificate"*|*"SSL routines"*) echo tls ;;
        # "no SMTP reply" is the backend's own send timeout; "request timed
        # out" is the HTTP layer's 503 on backends that had none.
        *"no SMTP reply"*|*"request timed out"*|*"network error"*|*"Connection error"*|*"timed out"*) echo connection ;;
        *) echo "other" ;;
    esac
}

mailpit_api_for() {
    case "$1" in
        mailpit-tls) echo "$API_MP_TLS" ;;
        mailpit-starttls) echo "$API_MP_STARTTLS" ;;
        mailpit-plain) echo "$API_MP_PLAIN" ;;
        *) echo "$API_SINK" ;;
    esac
}

delivered_to() {
    local api="$1" rcpt="$2" n
    for _ in 1 2 3 4 5; do
        n="$(curl -sS --max-time 5 -G "http://127.0.0.1:$api/api/v1/search" \
            --data-urlencode "query=to:$rcpt" | jq -r '.messages_count // 0' 2>/dev/null)"
        [ "${n:-0}" -gt 0 ] 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# run_cell SERVER MODE AUTH EXTRA EXPECTED  -> sets CELL_BODY, CELL_LOG
run_cell() {
    local server="$1" mode="$2" auth="$3" extra="$4" expected="$5"
    local id="$server/$mode/$auth${extra:+/$extra}"
    local rcpt
    rcpt="cell-$(echo "$id" | tr '/' '-')-$(date +%s%N | tail -c 7)@example.test"

    backend_env "$server" "$mode" "$auth" "$extra" || return 1
    if ! start_backend; then
        fail "$id: backend failed to start"
        return 1
    fi
    local token
    token="$(login)"
    if [ -z "$token" ]; then
        stop_backend
        fail "$id: admin login failed"
        return 1
    fi

    local out="$STATE_DIR/cell.json" code
    code="$(curl -sS --max-time "$CELL_TIMEOUT" -o "$out" -w '%{http_code}' \
        -X POST "$AK_URL/api/v1/admin/smtp/test" \
        -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
        -d "{\"to\":\"$rcpt\"}" 2>/dev/null)" || code="000"
    CELL_BODY="$(cat "$out" 2>/dev/null)"
    stop_backend
    CELL_LOG="$(grep -E 'SMTP test email failed|email sent successfully|SMTP_TLS|SMTP TLS' "$BACKEND_LOG" \
        | sed -e 's/\x1b\[[0-9;]*m//g' | tail -3)"

    local got
    # Backends before #4591 answer a failed test with a bare 500 "Internal
    # server error", so the backend's own log line is classified too.
    got="$(classify "$code" "$CELL_BODY $CELL_LOG")"
    if [ "$got" = "delivered-ish" ]; then
        if delivered_to "$(mailpit_api_for "$server")" "$rcpt"; then
            got=delivered
        else
            got=accepted-but-not-delivered
        fi
    fi

    local msg
    msg="$(echo "$CELL_BODY" | jq -r '.message // .error // empty' 2>/dev/null | head -c 400)"
    if [ "$got" = "$expected" ]; then
        pass "$id -> $got"
    else
        fail "$id -> got $got, expected $expected (HTTP $code: ${msg:-$CELL_BODY})"
    fi
    if [ "${SMTP_MATRIX_VERBOSE:-0}" = "1" ]; then
        echo "      HTTP $code: ${msg:-$CELL_BODY}"
        [ -n "$CELL_LOG" ] && echo "      log: $(sed -e 's/^.*SMTP test email failed //' <<<"$CELL_LOG" | head -1)"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# expectations
# ---------------------------------------------------------------------------
# expected SERVER MODE AUTH -> class
# "connection" is a plaintext client talking to an implicit-TLS port (or the
# reverse) until a timeout or a protocol error ends it.
expected() {
    local server="$1" mode="$2" auth="$3"
    local upgrade=0
    if [ "$auth" = badauth ]; then
        case "$server/$mode" in
            exchange/starttls*|mailpit-starttls/starttls*|mailpit-tls/tls|privateca/*) echo auth-rejected; return ;;
        esac
    fi
    case "$mode" in starttls|starttls-opportunistic) upgrade=1 ;; esac
    case "$server" in
        mailpit-tls)
            if [ "$mode" != "tls" ]; then echo connection
            elif [ "$auth" = auth ]; then echo delivered
            else echo auth-required; fi ;;
        mailpit-starttls)
            # Mailpit advertises AUTH before STARTTLS but answers it (and
            # MAIL) with "530 5.7.0 Must issue a STARTTLS command first".
            if [ "$mode" = tls ]; then echo tls
            elif [ "$mode" = none ]; then echo auth-required
            elif [ "$auth" = auth ]; then echo delivered
            else echo auth-required; fi ;;
        mailpit-plain)
            if [ "$mode" = tls ]; then echo tls
            elif [ "$mode" = starttls ]; then echo no-starttls
            elif [ "$auth" = auth ]; then echo delivered
            else echo auth-required; fi ;;
        exchange)
            if [ "$mode" = tls ]; then echo tls
            elif [ "$upgrade" = 1 ]; then
                [ "$auth" = auth ] && echo delivered || echo auth-required
            else
                [ "$auth" = auth ] && echo no-mechanism || echo auth-required
            fi ;;
        nostarttls)
            if [ "$mode" = tls ]; then echo tls
            elif [ "$mode" = starttls ]; then echo no-starttls
            else
                [ "$auth" = auth ] && echo no-mechanism || echo delivered
            fi ;;
        privateca)
            if [ "$mode" = tls ]; then echo tls
            elif [ "$upgrade" = 1 ]; then echo tls
            else
                [ "$auth" = auth ] && echo no-mechanism || echo auth-required
            fi ;;
    esac
}

run_matrix() {
    local modes=(tls none starttls)
    [ "$PROFILE" = "current" ] && modes+=(starttls-opportunistic)
    local servers=(mailpit-tls mailpit-starttls mailpit-plain exchange nostarttls privateca)
    local cells=()
    for s in "${servers[@]}"; do
        for m in "${modes[@]}"; do
            for a in auth noauth; do
                cells+=("$s $m $a - $(expected "$s" "$m" "$a")")
            done
        done
    done
    # Targeted cells: the reporter's 535, and the private-CA remedies.
    cells+=("exchange starttls badauth - $(expected exchange starttls badauth)")
    # Works on every backend: OpenSSL honours SSL_CERT_FILE.
    cells+=("privateca starttls auth sslcertfile delivered")
    if [ -n "${AK_IMAGE:-}" ] && [ -z "${AK_BIN:-}" ]; then
        cells+=("privateca starttls auth systemstore delivered")
    fi
    if [ "$PROFILE" = "current" ]; then
        cells+=("privateca starttls auth ca delivered")
        cells+=("privateca starttls auth ca-inline delivered")
        cells+=("privateca starttls auth customca delivered")
        cells+=("privateca starttls auth ca-over-custom delivered")
        cells+=("privateca starttls auth wrongca tls")
        cells+=("privateca starttls auth skipverify delivered")
        cells+=("privateca starttls-opportunistic auth ca delivered")
        cells+=("mailpit-tls tls auth skipverify delivered")
    fi

    echo "==> Running ${#cells[@]} cells (profile: $PROFILE)"
    local cell s m a x e
    for cell in "${cells[@]}"; do
        read -r s m a x e <<<"$cell"
        [ "$x" = "-" ] && x=""
        if [ -n "${SMTP_MATRIX_ONLY:-}" ] && ! echo "$s/$m/$a${x:+/$x}" | grep -qE "$SMTP_MATRIX_ONLY"; then
            continue
        fi
        run_cell "$s" "$m" "$a" "$x" "$e"
    done
}

summary() {
    echo ""
    echo "=============================================="
    echo "SMTP matrix: $PASSED passed, $FAILED failed"
    for c in "${FAILED_CELLS[@]}"; do echo "  - $c"; done
    echo "=============================================="
    [ "$FAILED" -eq 0 ]
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
cmd="${1:-run}"
case "$cmd" in
    up)
        check_prereqs
        prepare_state
        servers_up
        echo "SMTP servers are up (state in $STATE_DIR). Tear down with: $0 down"
        ;;
    down)
        servers_down
        rm -rf "$STATE_DIR"
        ;;
    cell)
        [ $# -ge 4 ] || { echo "usage: $0 cell SERVER MODE AUTH [EXTRA]"; exit 2; }
        check_prereqs
        check_backend
        prepare_state
        servers_up
        exp="$(expected "$2" "$3" "$4")"
        case "${5:-}" in
            "") ;;
            wrongca) exp=tls ;;
            *) exp=delivered ;;
        esac
        run_cell "$2" "$3" "$4" "${5:-}" "$exp"
        echo "response: $CELL_BODY"
        echo "log:      $CELL_LOG"
        ;;
    run)
        check_prereqs
        check_backend
        prepare_state
        STARTED_SERVERS=0
        running "$PREFIX-exchange" || STARTED_SERVERS=1
        if [ "$STARTED_SERVERS" = "1" ] && [ "${KEEP_SMTP_SERVERS:-0}" != "1" ]; then
            trap 'stop_backend; servers_down' EXIT
        else
            trap 'stop_backend' EXIT
        fi
        echo "==> Starting SMTP servers ($CONTAINER_RT)"
        servers_up
        run_matrix
        summary
        ;;
    *)
        echo "usage: $0 [run|up|down|cell SERVER MODE AUTH [EXTRA]]"
        exit 2
        ;;
esac
