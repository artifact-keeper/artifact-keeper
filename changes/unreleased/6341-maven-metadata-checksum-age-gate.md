---
section: Fixed
issues: [#6341, #6284]
---
- **The checksums of an age-gated `maven-metadata.xml` now match the document just served** (#6341, #6284). While a GA was still being dated (its `<lastUpdated>` inside the gate window and more undated versions than one listing probes), the `.sha1`, `.md5` and other sidecars ran the filter again, dated the next 64 POMs and hashed a longer list, so checksum validation failed and strict checksums (`-C`) rejected the metadata. The sidecars now filter with the dates already known and read no POMs, on a Remote and through a Virtual, and a Virtual no longer caches a sidecar's merge. The dates are kept per backend process, so with several replicas a sidecar matches only when it reaches the replica that served the document. Which versions a listing withholds while it is being dated is unchanged.
