---
section: Fixed
issues: [#4449]
---
- **Deleting the last tag of an OCI image pushed only by tag now also removes its `oci_manifests` record** (#4449). After the delete the manifest is no longer pullable by digest, but the record introduced in #4441 stayed and claimed it still existed. The record now goes when the delete removed the last tag and no live manifest row for the digest and no live parent index still references it. An image that was also pushed by digest, or a child manifest still listed by another tagged index, stays pullable and keeps its record.
