---
section: Fixed
issues: [#6199]
---
- **Nexus migrations copy assets that belong to no component** (#6199). The Nexus client only listed `/service/rest/v1/components`, so a file uploaded to a raw or Maven repository without coordinates, which only `/service/rest/v1/assets` returns, was never migrated, and a repository holding only such files completed with 0 items. After the component walk the client now pages through `/assets` with its continuation token and lists the raw files and Maven files without coordinates that no component already listed, deduplicated by path, with the sha256 and sha1 Nexus reports so checksum verification still applies. Metadata Nexus generates itself (npm packuments, `maven-metadata.xml` and its sidecars, other formats' indexes) stays out. Repositories whose assets all belong to components migrate the same items as before, at the cost of one more listing walk. A Nexus that answers 404 on `/assets` logs a warning and keeps the component listing.
