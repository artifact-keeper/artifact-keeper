# Source of ak-marker-1.0-1-any.pkg.tar.zst, the pacman fixture the
# backend/src/formats/pacman.rs and api/handlers/pacman.rs tests read.
# Rebuild inside an archlinux container: `PKGEXT=.pkg.tar.zst makepkg -f --nodeps`.
pkgname=ak-marker
pkgver=1.0
pkgrel=1
pkgdesc="Artifact Keeper pacman test marker"
arch=('any')
url="https://example.invalid/ak"
license=('MIT')
depends=('bash')
provides=('ak-marker-virt=1.0')
package() {
  install -Dm644 /dev/stdin "$pkgdir/usr/share/ak-marker/marker.txt" <<< "hello from ak-marker"
}
