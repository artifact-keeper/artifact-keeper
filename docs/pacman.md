# Arch Linux (pacman) repositories

Artifact Keeper hosts Arch Linux package repositories that `pacman` consumes
directly (#3343). Create a repository with `format: pacman` and
`repo_type: local`, upload packages built by `makepkg`, and point pacman at it.
The package databases are rendered on demand from the uploaded packages, so
there is no `repo-add` step and no database to keep in sync.

Remote (mirror) and virtual pacman repositories are not supported yet and
answer `501 Not Implemented`; see #4407.

## Endpoints

All routes live under `/pacman/{repo_key}`:

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/{package}` | Upload `{name}-{pkgver}-{pkgrel}-{arch}.pkg.tar.{zst,xz,gz,bz2}` (or `.pkg.tar`) |
| `PUT` | `/{package}.sig` | Attach the package's detached signature (binary or ASCII-armored) |
| `GET` | `/{arch}/{name}.db` | Package database (`{name}.db.tar.gz` also works) |
| `GET` | `/{arch}/{name}.files` | Database including file lists (`pacman -F`) |
| `GET` | `/{arch}/{name}.db.sig`, `/{arch}/{name}.files.sig` | Detached database signature (only when a signing key is attached) |
| `GET` | `/{arch}/{package}` | Package download |
| `GET` | `/{arch}/{package}.sig` | Uploaded package signature |
| `DELETE` | `/{arch}/{package}` | Delete a package |
| `GET` | `/gpg-key.asc` | The repository's public signing key |

`{name}` in the database filename is not checked, so the pacman section name
can be anything. Packages built for `arch=('any')` appear in every
architecture's database. Uploading a package whose filename disagrees with its
`.PKGINFO` is refused, and so is re-uploading an existing filename (409):
publish a new `pkgrel` instead. When several versions of a package are
uploaded, the database lists the most recently uploaded one, the way
`repo-add` replaces an existing entry.

The file list for `pacman -F` is read from the package at upload. A package
too large to list within the server's budget (8 GiB decompressed or 500,000
entries) is still published and installable; it just has no entry in the
`.files` database.

## Publishing

```bash
curl -u "$USER:$TOKEN" --upload-file foo-1.0-1-x86_64.pkg.tar.zst \
  https://registry.example.com/pacman/myrepo/foo-1.0-1-x86_64.pkg.tar.zst

# makepkg --sign writes foo-1.0-1-x86_64.pkg.tar.zst.sig next to the package:
curl -u "$USER:$TOKEN" --upload-file foo-1.0-1-x86_64.pkg.tar.zst.sig \
  https://registry.example.com/pacman/myrepo/foo-1.0-1-x86_64.pkg.tar.zst.sig
```

An uploaded signature is served as `{package}.sig` and also embedded in the
database as `%PGPSIG%`. The server never signs packages itself: the package
signature is the packager's.

## Consuming

```ini
# /etc/pacman.conf
[myrepo]
Server = https://registry.example.com/pacman/myrepo/$arch
```

For a private repository put the credentials in the URL
(`https://user:token@registry.example.com/pacman/myrepo/$arch`); pacman passes
them to the server as HTTP Basic authentication.

## Signing

Attach a signing key with `key_type: gpg` to the repository (`POST
/api/v1/signing/keys`, then `POST /api/v1/signing/repositories/{id}/config`
with `sign_metadata: true`) and every `{name}.db` and `{name}.files` gets a
detached signature at `.sig`, made over exactly the bytes pacman downloaded.
RSA keys are rejected for pacman repositories because pacman only verifies
OpenPGP signatures.

Trust the repository key once on each client:

```bash
curl -o myrepo.asc https://registry.example.com/pacman/myrepo/gpg-key.asc
pacman-key --add myrepo.asc
pacman-key --lsign-key <fingerprint>
```

With the repository key and the packager's key trusted, the default
`SigLevel = Required DatabaseOptional` works, and so does `SigLevel = Required`
(database signatures required too). Packages uploaded without a signature need
`PackageOptional` (for example `SigLevel = PackageOptional DatabaseRequired`).
Without a repository signing key the database `.sig` requests answer 404,
which `DatabaseOptional` accepts.

## Testing

`scripts/native-tests/test-pacman.sh` drives a real pacman in an archlinux
container against a running backend: it builds and signs a package with
`makepkg --sign`, uploads it, runs `pacman -Sy`, `-Sw`, `-S` and `-Fy` with
`SigLevel = Required`, then deletes the package and checks that pacman no
longer sees it.

```bash
REGISTRY_URL=http://localhost:8080 ./scripts/native-tests/test-pacman.sh
```
