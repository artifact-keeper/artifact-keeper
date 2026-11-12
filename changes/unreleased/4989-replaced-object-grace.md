---
section: Fixed
issues: [#4989]
---
- **An object replaced by a conditional write always gets the full storage GC grace window** ([#4989]). When a matched `If-Match` replaced content whose object already had a storage GC record (an earlier replace of the same bytes, a repository delete, a failed delete), the record kept its older `recorded_at`, so the object could be collected as soon as the replace committed. The record's `recorded_at` is now refreshed.
