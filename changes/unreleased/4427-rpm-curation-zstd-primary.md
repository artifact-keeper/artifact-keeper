---
section: Fixed
issues: [#4427]
---
- **RPM curation sync now ingests zstd, xz and bzip2 compressed `primary.xml` and no longer reports success after ingesting nothing** (#4427). The sync only gunzipped a `.gz` primary and read every other href as plain text, so an upstream whose `repomd.xml` lists `primary.xml.zst` (the createrepo_c default, common on Fedora and EL9 mirrors) parsed as 0 packages while the manual sync returned `succeeded: true`, silently emptying the staging repository. The primary is now decoded by its magic bytes (gzip, zstd, xz, bzip2 or plain), every codec is held to the existing ingest decompression budget, and a primary that declares packages but yields none (or a compressed href whose bytes are not that codec) fails the sync with a clear error instead.
