---
section: Fixed
issues: [#5364]
---
- **Hosted Conan uploads and downloads no longer hold the whole file in memory** ([#5364]). The recipe and package file routes of a hosted Conan repository read the stored object into memory before the response started, and took the upload body on the heap before writing it, so a `conan_package.tgz` of several hundred MB cost its full size per concurrent transfer and a burst of parallel `conan install` jobs got the backend OOMKilled. Downloads now stream from storage, and uploads are spooled to scratch (or to a staging object on S3, GCS or Azure) with their SHA-256 computed on the way, then written to their key, so the recorded checksum still describes exactly the stored bytes. A scannable file of a Remote that scans on proxy goes through the scan gate as before. Only `conanmanifest.txt`, which the revision check parses, is read into memory, and one larger than 16 MiB is now refused with `413`.
