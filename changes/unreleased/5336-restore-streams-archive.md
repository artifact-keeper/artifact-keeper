---
section: Fixed
issues: [#5336]
---
- **A restore streams the archive instead of holding it in memory** (#5336). The whole archive was downloaded and every entry decompressed into memory before a byte was restored, which also capped a restorable backup at 8 GiB of decompressed data. A restore now reads the archive from storage twice. The first pass checks the payload checksum while holding only the table dumps and the manifest, and writes nothing. The second streams each artifact to its repository storage location and refuses any entry that differs from what the first pass checked, so an archive that changes between the passes is never published. The 8 GiB ceiling now applies only to the table dumps and manifest a restore holds in memory, and the decompression budget scales with the archive's recorded size.
