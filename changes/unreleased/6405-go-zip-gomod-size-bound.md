---
section: Security
issues: [#6405]
---
- **An uploaded Go module zip can no longer inflate an unbounded `go.mod` entry while its metadata is read** (#6405). The upload-size limit bounds the compressed zip, not the decompressed entry, so a crafted `go.mod` could force the server to allocate and decompress an arbitrary amount of data. The entry is now read through the bounded archive helper with a 1 MiB cap and the shared entry-count cap, and an oversized `go.mod` is a validation error. When a zip contains both a nested module's `go.mod` and the requested module entry, the requested `module@version/go.mod` is read instead of whichever appeared first.
