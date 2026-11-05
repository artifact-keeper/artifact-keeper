---
section: Fixed
issues: [#5133]
---
- **Finalizing a whole-body OCI layer push no longer reads the layer back** (#5133). When a client sends the whole layer in the final `PUT ?digest=` (containerd does), the backend already has its digest from streaming it, so it no longer re-reads, rehashes and rewrites the layer before answering. Filesystem storage now moves staged uploads into place with a rename for this path, for `POST ?digest=` and for the staging object of a multi-part upload; object stores keep their server-side copy. This shortens the wait that containerd 2.3 and later limit to 30 s, which surfaced as `net/http: timeout awaiting response headers` on large layers. On object storage the copy still grows with layer size. `docs/operations/oci-reverse-proxy-timeouts.md` now covers client-side limits.
