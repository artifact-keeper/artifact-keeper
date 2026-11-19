---
section: Fixed
issues: [#6284]
---
- **With the Maven age gate on, `maven-metadata.xml.sha1` (and `.md5`, `.sha256`, `.sha512`) now match the metadata body while the GA is still being dated** (#6284). The metadata filter dates at most 64 undated versions per pass, and the checksum request ran a second pass that dated the next 64, so it hashed a longer document than the one just served: strict-checksum builds (`-C`, `checksumPolicy=fail`, Gradle dependency verification) rejected the metadata, and two downloads in a row listed different versions. A pass that leaves versions undated is now reused for 15 seconds, on a Remote and through a Virtual, so the body and every checksum sidecar come from the same filtered document; the next pass after that continues dating where it stopped.
