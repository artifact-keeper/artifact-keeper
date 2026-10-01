---
section: Fixed
issues: [#4149]
---
- **A remote conda repository can now serve the uncompressed `repodata.json` for every conda-forge subdir instead of answering 502** (#4149). The proxied fetch buffered upstream metadata under the 128 MiB `LARGE_METADATA_MAX_BYTES` ceiling, and conda-forge's plain `repodata.json` runs 160-200 MiB on every major subdir (linux-64, noarch, osx-arm64, linux-ppc64le), so any client requesting the uncompressed document — older conda releases and tooling without zstd support — got a bare 502 while the compressed `.zst`/`.bz2` variants proxied fine. The ceiling abort is now distinguished from a genuine upstream failure and the document is served through the streaming path instead: teed from upstream to the client and into the proxy cache without ever being buffered whole, exactly as oversized `.deb` and npm tarballs already were. Once the stream commits the cache entry, subsequent requests are served warm with no upstream round trip.
