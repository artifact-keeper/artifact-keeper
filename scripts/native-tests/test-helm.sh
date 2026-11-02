#!/bin/bash
# Helm native client E2E: ChartMuseum upload, duplicate 409, and the
# ChartMuseum-compatible `?force` overwrite (#4848).
#
# The `cm-push` plugin is NOT installed in alpine/helm (and this repo does not
# install external helm plugins at test time), so its request is reproduced
# with curl: POST /api/helm/{repo}/charts with a multipart `chart` part. The
# bare `?force` key is exactly what `helm cm-push --force` appends.
# The real helm CLI is used for repo add / repo update / pull against the
# native /helm/{repo} URL.
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
REGISTRY_URL="${REGISTRY_URL%/}"
REPO_KEY="${REPO_KEY:-test-helm}"
ADMIN_USER="${ADMIN_USER:-admin}"
CA_CERT="${CA_CERT:-}" # unused: REGISTRY_URL is plain HTTP in the e2e stack

# Throwaway e2e admin credential: defined once in the repository-root .env.test
# (#3490). Inside the e2e container only scripts/native-tests is mounted, so
# the helper below does not exist there; compose's env_file has already
# injected the same variables.
_ak_test_env="$(dirname "$0")/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"
: "${ADMIN_PASS:?ADMIN_PASS or AK_TEST_ADMIN_PASSWORD must be set}"

# Fixed name/version on purpose: the second upload in this run must collide
# with the first, and a re-run against a fresh stack repeats the same path.
CHART_NAME="helm-force-e2e"
TEST_VERSION="1.0.0"
NATIVE_REPO_URL="$REGISTRY_URL/helm/$REPO_KEY"
CM_PUSH_URL="$REGISTRY_URL/api/helm/$REPO_KEY/charts"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
RESP_BODY="$WORK_DIR/response.body"

# Keep helm's repo config and index cache inside this run's scratch dir so a
# second invocation in the same container cannot reuse a stale index.
export HELM_REPOSITORY_CONFIG="$WORK_DIR/helm/repositories.yaml"
export HELM_REPOSITORY_CACHE="$WORK_DIR/helm/cache"
mkdir -p "$WORK_DIR/helm/cache"

pass() { echo "PASS: $*"; }
die() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "==> Helm ?force E2E"
echo "    registry: $REGISTRY_URL"
echo "    repo:     $REPO_KEY"
echo "    chart:    $CHART_NAME-$TEST_VERSION"
echo "    CA cert:  ${CA_CERT:-<none: plain HTTP>}"

# ── Chart fixture ──────────────────────────────────────────────────────────
mkdir -p "$WORK_DIR/$CHART_NAME/templates"
cat >"$WORK_DIR/$CHART_NAME/Chart.yaml" <<EOF
apiVersion: v2
name: $CHART_NAME
description: "Helm ?force overwrite E2E (#4848)"
type: application
version: $TEST_VERSION
appVersion: "1.0.0"
EOF
cat >"$WORK_DIR/$CHART_NAME/templates/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}
data:
  marker: {{ .Values.e2eMarker | quote }}
EOF

write_values() {
    cat >"$WORK_DIR/$CHART_NAME/values.yaml" <<EOF
# Content marker: proves which upload the server is serving.
e2eMarker: "$1"
EOF
}

package_chart() { # $1 = destination dir; echoes the packaged tgz path
    mkdir -p "$1"
    helm package "$WORK_DIR/$CHART_NAME" --destination "$1" >/dev/null
    printf '%s/%s-%s.tgz\n' "$1" "$CHART_NAME" "$TEST_VERSION"
}

upload_chart() { # $1 = URL, $2 = tgz; sets HTTP_CODE
    # No -f/--fail-with-body here: a 409 is an expected outcome and must be
    # read, not turned into curl exit 22. Transport failures are still fatal.
    set +e
    HTTP_CODE=$(curl -sS -o "$RESP_BODY" -w '%{http_code}' \
        -u "$ADMIN_USER:$ADMIN_PASS" \
        -F "chart=@$2;type=application/gzip" \
        "$1")
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die "POST $1 failed at the transport level (curl exit $rc)"
}

assert_status() { # $1 = expected code, $2 = label
    if [ "$HTTP_CODE" != "$1" ]; then
        die "$2: expected HTTP $1, got $HTTP_CODE (body: $(cat "$RESP_BODY" 2>/dev/null || true))"
    fi
}

# ── 1/4: create ────────────────────────────────────────────────────────────
write_values "package-1-original"
CHART_V1="$(package_chart "$WORK_DIR/pkg1")"
[ -f "$CHART_V1" ] || die "helm package did not produce $CHART_V1"

echo "==> 1/4 upload (expect 201)"
upload_chart "$CM_PUSH_URL" "$CHART_V1"
assert_status 201 "initial upload"
pass "initial upload returned 201"

# ── 2/4: duplicate without ?force ──────────────────────────────────────────
echo "==> 2/4 duplicate upload without ?force (expect 409)"
upload_chart "$CM_PUSH_URL" "$CHART_V1"
assert_status 409 "duplicate upload"
grep -q "already exists" "$RESP_BODY" ||
    die "409 body lost the conflict message: $(cat "$RESP_BODY")"
pass "duplicate upload returned 409 and named the conflict"

# ── 3/4: overwrite with a bare ?force (no =true) ──────────────────────────
write_values "package-2-overwritten"
CHART_V2="$(package_chart "$WORK_DIR/pkg2")"
[ -f "$CHART_V2" ] || die "helm package did not produce $CHART_V2"

echo "==> 3/4 upload with bare '?force' (expect 201)"
upload_chart "$CM_PUSH_URL?force" "$CHART_V2"
assert_status 201 "force upload"
pass "force upload returned 201"

# The hosted index.yaml is generated from committed live rows on every
# request, and the handler commits before replying 201, so the new digest must
# be visible now. This closes the "201 but the index still advertises the old
# chart" gap.
curl -fsS -o "$WORK_DIR/index.yaml" "$NATIVE_REPO_URL/index.yaml" ||
    die "could not fetch $NATIVE_REPO_URL/index.yaml"
NEW_DIGEST="$(sha256sum "$CHART_V2" | awk '{print $1}')"
grep -q "$NEW_DIGEST" "$WORK_DIR/index.yaml" ||
    die "index.yaml does not advertise the re-uploaded sha256 ($NEW_DIGEST)"
pass "index.yaml advertises the overwritten chart digest"

# ── 4/4: pull through the real helm client ────────────────────────────────
echo "==> 4/4 helm repo add / update / pull"
helm repo add ak-force-e2e "$NATIVE_REPO_URL" \
    --username "$ADMIN_USER" --password "$ADMIN_PASS" --force-update >/dev/null
helm repo update ak-force-e2e >/dev/null

mkdir -p "$WORK_DIR/pulled"
helm pull "ak-force-e2e/$CHART_NAME" --version "$TEST_VERSION" \
    --destination "$WORK_DIR/pulled"
PULLED="$WORK_DIR/pulled/$CHART_NAME-$TEST_VERSION.tgz"
[ -f "$PULLED" ] || die "helm pull did not produce $PULLED"

if ! PULLED_VALUES="$(tar -xzOf "$PULLED" "$CHART_NAME/values.yaml")"; then
    die "pulled archive does not contain $CHART_NAME/values.yaml"
fi
case "$PULLED_VALUES" in
*package-2-overwritten*) ;;
*) die "pulled chart does not contain the overwritten marker: $PULLED_VALUES" ;;
esac
case "$PULLED_VALUES" in
*package-1-original*) die "pulled chart still carries the original content" ;;
esac

PULLED_SHA="$(sha256sum "$PULLED" | awk '{print $1}')"
[ "$PULLED_SHA" = "$NEW_DIGEST" ] ||
    die "pulled archive sha256 $PULLED_SHA != uploaded $NEW_DIGEST"
pass "helm pull returned the force-overwritten bytes"

echo ""
echo "Helm ?force E2E PASSED"
