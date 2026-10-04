---
section: Added
issues: [#3343]
---
- **Hosted Arch Linux package repositories for pacman** (#3343). A `pacman` repository accepts `makepkg` packages (`.pkg.tar.zst`/`.xz`/`.gz`/`.bz2`) under `/pacman/{repo}/`, reads `.PKGINFO` and the file list from each upload, and serves `{repo}.db` and `{repo}.files` rendered on demand in the same layout `repo-add` writes, so `pacman -Sy`, `-S` and `-F` work against it with no index step. Uploaded package signatures are served as `.sig` and embedded as `%PGPSIG%`, and a repository with a gpg signing key attached serves detached `.db.sig`/`.files.sig` signatures, so clients can run with `SigLevel = Required`. Packages are deleted with `DELETE /pacman/{repo}/{arch}/{package}` or the regular artifact API. Remote and virtual pacman repositories are not supported yet (#4407). See `docs/pacman.md`.
