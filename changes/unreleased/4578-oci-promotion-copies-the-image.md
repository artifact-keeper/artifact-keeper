---
section: Fixed
issues: [#4578]
---
- **Promoting a Docker/OCI image now makes it pullable from the target repository** (#4578). Promotion copied only the tag's `artifacts` row and its top-level manifest object, so a pull from the target answered `MANIFEST_UNKNOWN` and `tags/list` answered `NAME_UNKNOWN`, while the API reported `promoted: true`. This left `promotion_only` docker repositories with no way to receive a working image. The single, bulk and approval promotion paths now walk the promoted manifest in the source repository (an image index, its child manifests, and every config and layer blob), copy the missing objects into the target storage, and record the tag, the child manifests, the manifest references and the `oci_blobs` rows for the target in the same transaction as the promoted `artifacts` row. A source image with a missing manifest or blob fails the promotion instead of producing an empty tag.
