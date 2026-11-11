---
section: Fixed
issues: [#5336]
---
- **A backup streams its archive into storage instead of building it in memory** (#5336). Every artifact was read into memory before the archive was built, then the gzipped archive was copied for the upload and decompressed again to count its entries, so a full backup of a large instance ran out of memory. Each artifact now streams from its repository storage location into the tar.gz, the archive streams to the backup store as it is written, and the payload checksum and artifact count are computed on the way, so memory stays at a few chunks whatever the size of the backup. An artifact that cannot be opened is still left out and recorded as unreadable (#3170), but one whose read fails partway through now fails the run, because its entry is already in the archive.
