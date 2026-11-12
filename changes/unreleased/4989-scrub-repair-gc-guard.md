---
section: Fixed
issues: [#4989]
---
- **A storage scrub repair no longer races a storage GC delete of the same object** ([#4989]). The repair wrote its verified copy without telling storage GC, so a GC delete of the key could land just after the repair, or the repair could write an object GC had just removed. It now takes the key's GC journal slot, the guard uploads use (#4980), until the repaired object is re-verified. While a GC pass holds a fresh delete lease on the key the repair is skipped, and the finding says "storage GC is removing this object"; a later run retries it.
