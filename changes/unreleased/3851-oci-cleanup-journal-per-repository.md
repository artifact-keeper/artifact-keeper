---
section: Fixed
issues: [#3851]
---
- **Concurrent pushes of one blob to different repositories no longer risk a spurious `503 BLOB_UPLOAD_INVALID`** (#3851). The OCI upload cleanup journal kept one row per storage key across the whole database, so two pushes of the same digest to different repositories shared a row: the first to commit deleted it, and if that repository was deleted before the second push committed, the second push lost its only proof that a peer (not a cleanup sweep) had removed the row and was refused. Journal rows are now unique per repository and key (migration 243), so a push's row can only be cleared by a push to the same repository, its own repository's deletion, or a sweep. Content-addressed dedup is unchanged; on backends where repositories share one object namespace a cleanup sweep no longer deletes an object while another repository has a fresh journal row for it, and registration and the sweep's tombstone serialize per key.

  On shared-namespace backends a repository delete no longer deletes journaled `oci-blobs/<digest>` objects directly (another repository may have committed the same object); it records them as OCI GC candidates, and the candidate sweep deletes each one after its 24-hour grace unless another repository references it or holds a cleanup-journal row for it.
