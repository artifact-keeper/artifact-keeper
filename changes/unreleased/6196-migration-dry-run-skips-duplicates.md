---
section: Fixed
issues: [#6196]
---
- **A migration dry run now counts artifacts already in the destination as skipped** (#6196). The dry-run check ran ahead of the duplicate check, so with `conflict_resolution: skip` every existing artifact was reported as completed and its bytes added to the transfer estimate. A dry run now runs the same read-only skip checks as a real run first, so `completed_items` and `transferred_bytes` preview only what the real run would move. It still writes nothing.
