---
section: Fixed
issues: [#5096]
---
- **Image inspect and base-image info resolve a digest only within the requested repository and image** (#5096). `GET /api/v1/repositories/{key}/image-inspect` and `GET /api/v1/repositories/{key}/image-builds/base-info` resolved a tag through the image's tags but accepted any `sha256:` digest as given and read the manifest, config and provenance by digest. On storage shared by several repositories, that described a manifest stored for another repository or image. A digest now resolves when a tag of the image names it, when the image's catalog records it (an untagged push by digest), or when it is a platform or attestation child of an index that belongs to the image. Any other digest answers exactly like one that does not exist: 404 for inspect, `found: false` for base-info.
