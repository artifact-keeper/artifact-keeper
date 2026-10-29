---
section: Fixed
issues: [#5111]
---
- **Image inspect reads config and provenance only from the requesting repository** (#5111). `GET /api/v1/repositories/{key}/image-inspect` and `GET /api/v1/repositories/{key}/image-builds/base-info` read the config blob and the provenance attestation layer that a manifest names by digest alone. A manifest can name any blob digest, so on storage shared by several repositories that could describe a blob recorded only for another repository. Both blobs are now read only when the repository records them, as its hosted blob downloads require: an unrecorded config answers exactly like a missing one (404 for inspect, `found: false` for base-info), and unrecorded provenance is left out like missing provenance. A missing object's 404 message no longer carries the storage backend's error text.
