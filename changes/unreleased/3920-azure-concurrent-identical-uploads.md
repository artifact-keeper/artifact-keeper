---
section: Fixed
issues: [#3920]
---
- **Concurrent uploads of byte-identical content no longer fail with 500 on the Azure backend** (#3920). Two uploads of the same content stream blocks to the same content-addressed blob; Azure keeps one uncommitted block list per blob, so when the first upload committed, the second's staged blocks were discarded and its Put Block List failed with `400 InvalidBlockList`, surfacing as `500 STORAGE_ERROR`. A commit that fails this way now checks the blob the other writer committed and, when it is byte-for-byte what this upload streamed (same size and SHA-256), treats the upload as successful. A commit that lost to different content still fails.
