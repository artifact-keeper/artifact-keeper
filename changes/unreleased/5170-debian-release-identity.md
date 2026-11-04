---
section: Fixed
issues: [#5170, #4988]
---
- **Scan-on-proxy grades a Debian package against its own suite's release, and a signed `.apk` keeps its stored `.PKGINFO` metadata** (#5170, #4988). A package whose version marker names another Debian release than its suite (`+deb11u1` in a Debian 12 suite) is now inconclusive, so `fail_closed` withholds it (423) instead of grading it against either feed. When a package backported from a stable update carries two markers (`+deb13u1~bpo12+1`), the rightmost is the one read; it used to be graded as Debian 13 in a Debian 12 backports suite. A marker on an Ubuntu or derivative package is not compared.

  The gate no longer falls back to "the one release every cached suite agrees on", which could be another suite's. It now finds the suite the way apt's traffic leaves it findable: indexes fetched under `by-hash/`, `_all` packages in an architecture's index, the security archive's `pool/updates/`, Ubuntu's two-stream `Packages.xz`, a `Release` or index past its cache TTL, and, when a client with current lists fetched no index, the index the cached `Release` names, fetched and verified against it. A package no such index lists is graded on its version marker, or is otherwise inconclusive. `bookworm-updates` and its like (`Version: 12-updates`) now name their release, which also stops them leaving every unmarked package of a Remote that caches them withheld.

  Debian's own archive currently has packages this withholds under `fail_closed`: `designate` (`+deb11u1` in `bookworm-security`), `curl` (`+deb13u2~bpo13+1` in `bookworm-backports`) and a few `+deb13uN` versions in `testing`. See `docs/security/scan-on-proxy.md`.

  `AlpineHandler::extract_pkginfo` now reads every gzip member, through the reader the scan gate uses, so `parse_metadata` no longer drops the `.PKGINFO` of a signed package. Only the core format-handler test path reads that document with a package body, and it does not read `pkginfo`.
