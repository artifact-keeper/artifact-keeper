---
section: Fixed
issues: [#5169, #5004]
---
- **A Remote OCI repository now repairs a corrupt stored blob from its upstream instead of failing every pull of that layer** (#5169, #5004). A stored copy that no longer hashes to its digest answered `502 STORED_OBJECT_INTEGRITY` until an operator removed it by hand. It is now treated as a cache miss: the blob is refetched, checked against its digest and recorded size, the corrupt object is overwritten, and the pull is answered from the store. If the upstream fails or its bytes do not match, the pull keeps the `502` and the object is left alone. A blob over 4 MiB is only found corrupt after its `200` went out, so that transfer is still aborted and the repair runs behind it for the client's retry. Hosted repositories keep the `502`. See `docs/operations/download-integrity.md`.
