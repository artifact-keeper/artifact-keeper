#!/bin/bash
# Arch Linux pacman native client test (#3343)
#
# Drives a real pacman (archlinux container) against a hosted pacman
# repository:
#   1. creates a local `pacman` repository and attaches a gpg signing key
#   2. builds a package with makepkg and signs it with a throwaway packager key
#   3. uploads the package and its detached .sig through the native API
#   4. pacman -Sy / -Sw / -S / -Fy with `SigLevel = Required`, so both the
#      database signature (repository key) and the package signature
#      (packager key) are verified by pacman itself
#   5. deletes the package and checks pacman no longer sees it
#
# The client steps run in an archlinux container on the host network, so the
# registry URL must be reachable from the host (e.g. a backend started with
# `cargo run`). Requires curl, jq and podman (or docker), and an amd64 host:
# the official archlinux image is published for x86_64 only. Building the
# package installs base-devel from the live Arch mirrors.
#
# Usage:
#   ./test-pacman.sh                                   # localhost:30080
#   REGISTRY_URL=http://localhost:8080 ./test-pacman.sh
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:30080}"
REPO_KEY="${PACMAN_REPO_KEY:-test-pacman-$(date +%s)}"
ARCH_IMAGE="${ARCH_IMAGE:-docker.io/library/archlinux:latest}"
ADMIN_USER="${ADMIN_USER:-admin}"
# Throwaway e2e admin credential, defined once in the repository-root
# .env.test (#3490).
_ak_test_env="$(dirname "$0")/../lib/test-env.sh"
# shellcheck source=/dev/null
[ -r "$_ak_test_env" ] && . "$_ak_test_env"
ADMIN_PASS="${ADMIN_PASS:-${AK_TEST_ADMIN_PASSWORD:-}}"
PKG_NAME="ak-native-test"
PKG_VER="1.$(date +%s)"

RUNTIME="${CONTAINER_RUNTIME:-}"
if [ -z "$RUNTIME" ]; then
    if command -v podman >/dev/null; then RUNTIME=podman
    elif command -v docker >/dev/null; then RUNTIME=docker
    else echo "SKIP: neither podman nor docker found"; exit 0
    fi
fi
command -v curl >/dev/null || { echo "SKIP: curl not found"; exit 0; }
command -v jq >/dev/null || { echo "SKIP: jq not found"; exit 0; }

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

WORK_DIR="$(mktemp -d)"
chmod 777 "$WORK_DIR"
TOKEN=""
cleanup() {
    # The repository (and the signing key it cascades) goes on every exit,
    # not just the successful one.
    if [ -n "$TOKEN" ]; then
        curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" \
            "$REGISTRY_URL/api/v1/repositories/$REPO_KEY" || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "==> pacman native client test"
echo "Registry: $REGISTRY_URL  repo: $REPO_KEY  package: $PKG_NAME $PKG_VER-1"

# ---- 1. repository + signing key ------------------------------------------
TOKEN=$(curl -sf -X POST "$REGISTRY_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq -r .access_token) \
    || fail "login"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login"
AUTH=(-H "Authorization: Bearer $TOKEN")

REPO_ID=$(curl -sf -X POST "$REGISTRY_URL/api/v1/repositories" "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"$REPO_KEY\",\"name\":\"pacman native test\",\"format\":\"pacman\",\"repo_type\":\"local\",\"is_public\":false}" \
    | jq -r .id) || fail "create repository"
[ -n "$REPO_ID" ] && [ "$REPO_ID" != "null" ] || fail "create repository"
pass "created private pacman repository $REPO_KEY"

KEY_ID=$(curl -sf -X POST "$REGISTRY_URL/api/v1/signing/keys" "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"repository_id\":\"$REPO_ID\",\"name\":\"$REPO_KEY-signing\",\"key_type\":\"gpg\",\"algorithm\":\"rsa2048\",\"uid_name\":\"AK pacman test\",\"uid_email\":\"pacman-test@example.invalid\"}" \
    | jq -r .id) || fail "create signing key"
[ -n "$KEY_ID" ] && [ "$KEY_ID" != "null" ] || fail "create signing key"
curl -sf -X POST "$REGISTRY_URL/api/v1/signing/repositories/$REPO_ID/config" "${AUTH[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"signing_key_id\":\"$KEY_ID\",\"sign_metadata\":true}" >/dev/null || fail "signing config"
curl -sf "${AUTH[@]}" "$REGISTRY_URL/pacman/$REPO_KEY/gpg-key.asc" -o "$WORK_DIR/repo-key.asc" \
    || fail "fetch repository key"
pass "repository signing key attached"

# ---- 2. build and sign a package ------------------------------------------
cat > "$WORK_DIR/build.sh" <<EOF
set -euo pipefail
pacman -Syu --noconfirm --needed base-devel >/dev/null
useradd -m builder
install -d -o builder /home/builder/pkg
cat > /home/builder/pkg/PKGBUILD <<'P'
pkgname=$PKG_NAME
pkgver=$PKG_VER
pkgrel=1
pkgdesc="Artifact Keeper pacman native test package"
arch=('any')
url="https://example.invalid/ak"
license=('MIT')
depends=('bash')
package() {
  install -Dm644 /dev/stdin "\$pkgdir/usr/share/$PKG_NAME/hello.txt" <<< "hello from $PKG_NAME $PKG_VER"
}
P
chown builder /home/builder/pkg/PKGBUILD
su builder -c '
  set -e
  gpg --batch --pinentry-mode loopback --passphrase "" \
      --quick-gen-key "AK packager <packager@example.invalid>" rsa2048 sign never 2>/dev/null
  cd /home/builder/pkg && PKGEXT=.pkg.tar.zst makepkg --sign --nodeps >/dev/null
  gpg --armor --export > /work/packager-key.asc
'
cp /home/builder/pkg/*.pkg.tar.zst /home/builder/pkg/*.pkg.tar.zst.sig /work/
EOF
"$RUNTIME" run --rm --network host -v "$WORK_DIR:/work:Z" "$ARCH_IMAGE" bash /work/build.sh \
    || fail "makepkg build"
PKG_FILE="$PKG_NAME-$PKG_VER-1-any.pkg.tar.zst"
[ -f "$WORK_DIR/$PKG_FILE" ] && [ -f "$WORK_DIR/$PKG_FILE.sig" ] || fail "package not built"
pass "built and signed $PKG_FILE"

# ---- 3. upload package + signature ----------------------------------------
STATUS=$(curl -s -o "$WORK_DIR/upload.json" -w '%{http_code}' -X PUT "${AUTH[@]}" \
    --data-binary "@$WORK_DIR/$PKG_FILE" "$REGISTRY_URL/pacman/$REPO_KEY/$PKG_FILE")
[ "$STATUS" = 201 ] || fail "upload package: HTTP $STATUS $(cat "$WORK_DIR/upload.json")"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "${AUTH[@]}" \
    --data-binary "@$WORK_DIR/$PKG_FILE.sig" "$REGISTRY_URL/pacman/$REPO_KEY/$PKG_FILE.sig")
[ "$STATUS" = 201 ] || fail "upload signature: HTTP $STATUS"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "${AUTH[@]}" \
    --data-binary "@$WORK_DIR/$PKG_FILE" "$REGISTRY_URL/pacman/$REPO_KEY/$PKG_FILE")
[ "$STATUS" = 409 ] || fail "duplicate upload should be 409, got $STATUS"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$REGISTRY_URL/pacman/$REPO_KEY/x86_64/$REPO_KEY.db")
[ "$STATUS" = 401 ] || fail "anonymous read of a private repo should be 401, got $STATUS"
pass "uploaded package and signature"

# ---- 4. pacman -Sy / -Sw / -S / -Fy ---------------------------------------
# Credentials ride in the Server URL (pacman's curl turns them into Basic
# auth), which is how a private repository is consumed.
SERVER_BASE="${REGISTRY_URL/:\/\//://$ADMIN_USER:$ADMIN_PASS@}"
cat > "$WORK_DIR/client.sh" <<EOF
set -euo pipefail
cat > /tmp/pacman.conf <<C
[options]
Architecture = auto
SigLevel = Required
LocalFileSigLevel = Optional

[$REPO_KEY]
Server = $SERVER_BASE/pacman/$REPO_KEY/\\\$arch
C
pacman-key --init >/dev/null 2>&1
for key in /work/repo-key.asc /work/packager-key.asc; do
  pacman-key --add "\$key" >/dev/null 2>&1
  fpr=\$(gpg --with-colons --import-options show-only --import "\$key" | awk -F: '/^fpr/ {print \$10; exit}')
  pacman-key --lsign-key "\$fpr" >/dev/null 2>&1
done
P="pacman --config /tmp/pacman.conf --noconfirm"
\$P -Sy
if [ "\${1:-}" = deleted ]; then
  if \$P -Si $PKG_NAME >/dev/null 2>&1; then
    echo "package still listed after delete"; exit 1
  fi
  echo DELETE-OK
  exit 0
fi
\$P -Si $PKG_NAME | grep -q "Version *: $PKG_VER-1"
\$P -Sw $PKG_NAME
test -f /var/cache/pacman/pkg/$PKG_FILE
\$P -S $PKG_NAME
grep -q "hello from $PKG_NAME $PKG_VER" /usr/share/$PKG_NAME/hello.txt
\$P -Fy
\$P -Fl $PKG_NAME | grep -q "usr/share/$PKG_NAME/hello.txt"
echo CLIENT-OK
EOF
"$RUNTIME" run --rm --network host -v "$WORK_DIR:/work:Z" "$ARCH_IMAGE" bash /work/client.sh \
    | tee "$WORK_DIR/client.log" | sed 's/^/    /' || true
grep -q CLIENT-OK "$WORK_DIR/client.log" || fail "pacman client run"
pass "pacman -Sy, -Sw, -S and -Fy verified the signed repository"

# ---- 5. delete -------------------------------------------------------------
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${AUTH[@]}" \
    "$REGISTRY_URL/pacman/$REPO_KEY/x86_64/$PKG_FILE")
[ "$STATUS" = 204 ] || fail "delete: HTTP $STATUS"
# The (now empty) database is still signed, so this run keeps SigLevel=Required.
"$RUNTIME" run --rm --network host -v "$WORK_DIR:/work:Z" "$ARCH_IMAGE" bash /work/client.sh deleted \
    | tee "$WORK_DIR/deleted.log" | sed 's/^/    /' || true
grep -q DELETE-OK "$WORK_DIR/deleted.log" || fail "package still visible after delete"
pass "deleted package is gone from the database"

echo ""
echo "pacman native client test PASSED"
