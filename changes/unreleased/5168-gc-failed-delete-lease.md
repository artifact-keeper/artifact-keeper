---
section: Fixed
issues: [#5168, #4989]
---
- **A failed storage GC delete no longer blocks uploads of the same content for 15 minutes** (#5168, #4989). When the object-store delete failed, the `oci_gc_candidates` row stayed leased, so the upload commit guard answered 503 for that content until the lease aged out, although the delete was over and the object still stored. The failed delete now clears its own lease, as the repository-delete purge already did. The row stays and the candidate sweep still retries the delete on the same schedule with its reference re-check. A lease another GC claim or repository delete has taken since is left alone, because that delete may still land.
