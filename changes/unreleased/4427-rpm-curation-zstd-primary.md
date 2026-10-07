---
section: Fixed
issues: [#4427]
---
- **RPM curation sync now ingests zstd, xz and bzip2 compressed `primary.xml`, and a sync that ingests nothing reports failure** (#4427). Before this fix, the sync only gunzipped a `.gz` primary and read every other href as plain text. An upstream whose `repomd.xml` lists `primary.xml.zst` therefore parsed as 0 packages, while the manual sync still returned `succeeded: true`. That is the createrepo_c default, common on Fedora and EL9 mirrors, so the staging repository was silently emptied.

  What changed:
  - The primary is decoded by its magic bytes (gzip, zstd, xz, bzip2 or plain), and every codec is held to the existing ingest decompression budget (`MAX_INGEST_DECOMPRESSED_BYTES`, 128 MiB by default). Note that a Fedora 44 Everything x86_64 primary decodes to about 177 MiB, so mirroring it requires raising that variable.
  - A plain `primary.xml` must now be valid UTF-8, as the format requires; it is no longer read lossily.
  - These cases now fail that staging repository's sync (manual trigger: `succeeded: false`; the repository retries on the next tick) instead of reporting success:
    - a primary that declares packages but yields none
    - a compressed href whose bytes are not that codec
    - a primary that cannot be decoded
    - a repomd or primary fetch failure
    - a GPG refusal (no trusted key without `curation_allow_unverified`, missing `.asc`, or a failed verification)
    - a checksum-chain mismatch
  - A failing repository no longer aborts the scheduled sweep for the remaining repositories. Repositories are now swept least-recently-synced first.
