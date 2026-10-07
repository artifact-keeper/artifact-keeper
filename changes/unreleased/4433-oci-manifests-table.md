---
section: Changed
issues: [#4433, #1683]
---
- **The OCI registry now records every committed manifest in a first-class `oci_manifests` table, independent of its tags** (#4433, #1683). Manifest existence used to be inferred from `oci_tags`, so a manifest whose last tag was gone became invisible even though its bytes were still stored. Migration 268 adds the table (online-safe: a new, empty table); every push, proxy-cache fill and migration import writes its row in the same transaction as the tag, a delete by digest removes it once nothing (no tag, no parent index) still holds the manifest, and a background startup backfill records manifests pushed before the upgrade (reading each body from storage, idempotent, failures logged and retried on the next start). Nothing reads the table yet: moving manifest GET/HEAD/DELETE, the Referrers API and storage GC onto it follows in later releases.
