---
section: Fixed
issues: [#5478]
---
- **`.apk` downloads honour `Range`, so a client that fetches an archive as separate spans gets the bytes it asked for** (#5478). The alpine package download ignored the `Range` request header and answered `200` with the whole archive. An apk consumer that fetches a package's signature, control and data sections as three ranged `GET`s and checksums each span therefore checksummed the whole file three times and failed all three, which makes an Alpine mirror unusable to those clients. The alpine package download now answers `206` with the requested window and `416` for an unsatisfiable one, reusing the existing `parse_byte_range` / `slice_byte_stream` / `ranged_stream_response` helpers (#1847) on the hosted, proxy-cached and cold-cache arms alike, and it advertises `Accept-Ranges: bytes` on an unranged serve so a client that probes first knows it may range at all.
