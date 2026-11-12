#!/bin/sh
# Sandbox sources the worker must refuse BEFORE any guest starts (#5446,
# #5448), checked end to end through `ak-mcp-introspector sandbox-probe`.
#
#   #5446  an npm or PyPI guest installs only from this AK instance: a
#          registryBaseUrl on another origin, with userinfo, a query, dot
#          segments, the wrong scheme or port, or none at all is refused.
#   #5448  an OCI guest runs only a canonical `<ak-host>/<repo>/<image>@sha256:`
#          reference: a malformed digest, an unsafe path, another origin,
#          trailing arguments, or a source-changing field next to it is
#          refused.
#
# The unit tests (`registry_forms_are_refused` in sandbox/source.rs,
# `oci_spec_refuses_malformed_references_and_source_overrides` in sandbox.rs)
# check the renderer. This checks the shipped binary and the runner it is
# configured with: each case must answer `unsupported` with an error that
# does not echo the attacker's host, and no guest may be started for it.
#
# Two ways to see a guest start:
#   ENGINE=docker|podman  (CI: the real OCI runner, e.g. RUNTIME=runsc) --
#     any `create` event for a container labelled com.artifactkeeper.mcp-sandbox
#     during the case counts as a start. CONTROL_JOB, a job the runner can
#     really run, proves that detection works.
#   ENGINE unset          (local) -- an external runner stub
#     (AK_MCP_SANDBOX_COMMAND) logs every launch it is asked for; a canonical
#     npm job is the control.
#
# Usage: BIN=target/debug/ak-mcp-introspector [ENGINE=docker RUNTIME=runsc
#        CONTROL_JOB=job.json] sh source-refusal-check.sh
# Exit 0 when every case is refused without a guest and the control starts.
set -u

BIN="${BIN:?set BIN to the ak-mcp-introspector binary}"
ENGINE="${ENGINE:-}"
AK="https://ak.example.com"
LABEL="com.artifactkeeper.mcp-sandbox"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0

if [ -n "$ENGINE" ]; then
  export AK_MCP_SANDBOX_ENGINE="$ENGINE"
  export AK_MCP_SANDBOX_RUNTIME="${RUNTIME:-runsc}"
  unset AK_MCP_SANDBOX_COMMAND
else
  cat > "$work/launcher" <<EOF
#!/bin/sh
echo launched >> "$work/launches"
exit 3
EOF
  chmod +x "$work/launcher"
  export AK_MCP_SANDBOX_COMMAND="$work/launcher"
fi

# Did the run that started at $1 (epoch seconds) start a guest?
started_guest() {
  if [ -n "$ENGINE" ]; then
    [ -n "$("$ENGINE" events --since "$1" --until "$(date +%s)" \
              --filter "label=$LABEL" --filter event=create --format '{{.ID}}' 2>/dev/null)" ]
  else
    [ -s "$work/launches" ]
  fi
}

probe() { # <job file> -> $work/out.json, $work/err.txt; prints the outcome
  : > "$work/launches"
  "$BIN" sandbox-probe "$1" > "$work/out.json" 2> "$work/err.txt"
  jq -r '.outcome // "none"' "$work/out.json" 2>/dev/null || echo none
}

refused() { # <label> <target JSON>
  label="$1"
  jq -n --arg ak "$AK" --argjson t "$2" '{jobId: "refusal-check", akBaseUrl: $ak, target: $t}' > "$work/job.json"
  since="$(date +%s)"
  outcome="$(probe "$work/job.json")"
  err="$(jq -r '.error // ""' "$work/out.json" 2>/dev/null)"
  sleep 1
  if [ "$outcome" != "unsupported" ]; then
    echo "FAIL $label: outcome '$outcome', want unsupported (error: ${err:-$(head -c 200 "$work/err.txt")})"
    fails=$((fails + 1))
  elif started_guest "$since"; then
    echo "FAIL $label: refused, but a guest was started first"
    fails=$((fails + 1))
  elif [ -z "$err" ] || printf '%s' "$err" | grep -q 'evil\.test'; then
    echo "FAIL $label: refusal error is empty or echoes the attacker's host: $err"
    fails=$((fails + 1))
  else
    echo "ok   $label: unsupported, no guest ($(printf '%s' "$err" | head -c 100))"
  fi
}

pkg() { # <kind> <registryBaseUrl JSON or null> [extra jq]
  jq -cn --arg k "$1" --argjson r "$2" '
    {type: "package", index: 0, registryType: $k,
     package: ({registryType: $k,
                identifier: (if $k == "npm" then "@acme/weather" else "acme-mcp" end),
                version: "1.2.3", transport: {type: "stdio"}}
               + (if $r == null then {} else {registryBaseUrl: $r} end))}'
}
oci() { # <identifier> [extra package fields JSON]
  x="${2:-}"; [ -n "$x" ] || x='{}'
  jq -cn --arg id "$1" --argjson x "$x" \
    '{type: "package", index: 0, registryType: "oci",
      package: ({registryType: "oci", identifier: $id, transport: {type: "stdio"}} + $x)}'
}

echo "== #5446: npm and PyPI guests install only from this AK instance"
for k in npm pypi; do
  refused "$k: public registry" "$(pkg "$k" '"https://registry.npmjs.org/"')"
  refused "$k: host-prefix confusion" "$(pkg "$k" "\"https://ak.example.com.evil.test/$k/r\"")"
  refused "$k: userinfo" "$(pkg "$k" "\"https://ak.example.com@evil.test/$k/r\"")"
  refused "$k: plain http" "$(pkg "$k" "\"http://ak.example.com/$k/r\"")"
  refused "$k: another port" "$(pkg "$k" "\"https://ak.example.com:8443/$k/r\"")"
  refused "$k: query override" "$(pkg "$k" "\"https://ak.example.com/$k/r?registry=https://evil.test\"")"
  refused "$k: dot segments" "$(pkg "$k" "\"https://ak.example.com/$k/x/../r\"")"
  refused "$k: encoded path" "$(pkg "$k" "\"https://ak.example.com/$k/r%2F..%2Fevil\"")"
  refused "$k: no registryBaseUrl" "$(pkg "$k" null)"
done

echo "== #5448: OCI guests run only a canonical AK image reference"
d="$(printf 'a%.0s' $(seq 64))"
refused "oci: short digest" "$(oci "ak.example.com/oci/acme/mcp@sha256:abc")"
refused "oci: uppercase digest" "$(oci "ak.example.com/oci/acme/mcp@sha256:$(printf 'A%.0s' $(seq 64))")"
refused "oci: two digests" "$(oci "ak.example.com/oci/acme/mcp@sha256:$d@sha256:$d")"
refused "oci: path traversal" "$(oci "ak.example.com/oci/acme/../mcp@sha256:$d")"
refused "oci: trailing argument" "$(oci "ak.example.com/oci/acme/mcp@sha256:$d --network=host")"
refused "oci: another origin" "$(oci "evil.test/ak.example.com/oci/acme/mcp@sha256:$d")"
refused "oci: host-prefix confusion" "$(oci "ak.example.com.evil.test/oci/acme/mcp@sha256:$d")"
refused "oci: tag and digest" "$(oci "ak.example.com/oci/acme/mcp:1:2@sha256:$d")"
refused "oci: source override (registryBaseUrl)" "$(oci "ak.example.com/oci/acme/mcp@sha256:$d" '{"registryBaseUrl": "https://evil.test"}')"
refused "oci: source override (version)" "$(oci "ak.example.com/oci/acme/mcp@sha256:$d" '{"version": "https://evil.test"}')"

echo "== CONTROL: a job the runner accepts does start a guest"
if [ -n "$ENGINE" ]; then
  ctl="${CONTROL_JOB:?with ENGINE set, CONTROL_JOB must name a job the runner can run}"
else
  jq -n --arg ak "$AK" --argjson t "$(pkg npm "\"$AK/npm/npm-virtual\"")" \
    '{jobId: "refusal-check-control", akBaseUrl: $ak, target: $t}' > "$work/control.json"
  ctl="$work/control.json"
fi
since="$(date +%s)"
outcome="$(probe "$ctl")"
sleep 1
if [ "$outcome" = "unsupported" ] || [ "$outcome" = "none" ] || ! started_guest "$since"; then
  echo "FAIL control: outcome '$outcome'; a guest must start, or the refusal cases prove nothing"
  head -c 400 "$work/err.txt"; echo
  fails=$((fails + 1))
else
  echo "ok   control: outcome '$outcome', guest started"
fi
if [ -n "$ENGINE" ]; then
  test -z "$("$ENGINE" ps -aq --filter "label=$LABEL")" || { echo "FAIL a sandbox guest was left behind"; fails=$((fails + 1)); }
fi

echo
if [ "$fails" -gt 0 ]; then
  echo "source-refusal-check: $fails FAILED"
  exit 1
fi
echo "source-refusal-check: every source refused before a guest started"
