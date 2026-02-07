#!/bin/bash
# Red Team Test 01: Service Discovery & Port Scanning
# Scans the backend host for unexpected open ports.

source "$(dirname "$0")/../lib.sh"

set -uo pipefail

header "Service Discovery & Port Scanning"

# Extract hostname from REGISTRY_URL
BACKEND_HOST="${REGISTRY_URL#*://}"
BACKEND_HOST="${BACKEND_HOST%%:*}"
BACKEND_HOST="${BACKEND_HOST%%/*}"

info "Target host: ${BACKEND_HOST}"
info "Running nmap TCP connect scan..."

# Known expected ports
EXPECTED_PORTS="8080 9090"

# Run nmap scan on common ports (top 1000)
NMAP_OUTPUT=$(nmap -sT -T4 "$BACKEND_HOST" 2>&1) || true

info "Scan complete"

if echo "$NMAP_OUTPUT" | grep -q "Host seems down\|0 hosts up"; then
    warn "Host appears down or blocking probes - cannot complete scan"
    add_finding "INFO" "recon/host-down" \
        "Target host ${BACKEND_HOST} appears down or is blocking scan probes" \
        "$NMAP_OUTPUT"
    exit 0
fi

# Parse open ports from nmap output
# nmap output format: "8080/tcp open  http-proxy"
OPEN_PORTS=$(echo "$NMAP_OUTPUT" | grep "^[0-9]*/tcp.*open" | awk -F'/' '{print $1}') || true

if [ -z "$OPEN_PORTS" ]; then
    warn "No open ports detected - host may be filtering all traffic"
    add_finding "INFO" "recon/no-open-ports" \
        "No open TCP ports detected on ${BACKEND_HOST}" \
        "$NMAP_OUTPUT"
    exit 0
fi

info "Open ports found: $(echo $OPEN_PORTS | tr '\n' ' ')"

# Check each open port
UNEXPECTED_FOUND=false
for port in $OPEN_PORTS; do
    is_expected=false
    for expected in $EXPECTED_PORTS; do
        if [ "$port" = "$expected" ]; then
            is_expected=true
            break
        fi
    done

    if [ "$is_expected" = true ]; then
        pass "Expected port ${port}/tcp is open"
    else
        fail "Unexpected port ${port}/tcp is open"
        UNEXPECTED_FOUND=true

        # Get the service name from nmap output for the finding
        SERVICE_INFO=$(echo "$NMAP_OUTPUT" | grep "^${port}/tcp" | awk '{print $3}') || true
        add_finding "MEDIUM" "recon/unexpected-port" \
            "Unexpected open port ${port}/tcp (service: ${SERVICE_INFO:-unknown}) on ${BACKEND_HOST}" \
            "Port ${port}/tcp detected as open. Service: ${SERVICE_INFO:-unknown}. Only ports 8080 (HTTP) and 9090 (gRPC) are expected."
    fi
done

# Verify expected ports are actually open
for expected in $EXPECTED_PORTS; do
    found=false
    for port in $OPEN_PORTS; do
        if [ "$port" = "$expected" ]; then
            found=true
            break
        fi
    done

    if [ "$found" = false ]; then
        warn "Expected port ${expected}/tcp is not open"
    fi
done

if [ "$UNEXPECTED_FOUND" = false ]; then
    pass "No unexpected ports found - only expected services are exposed"
fi

exit 0
