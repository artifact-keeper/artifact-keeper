---
section: Fixed
issues: [#5992]
---
- **A rescan is held back per digest while any artifact holding it has a scan queued, and a busy instance no longer re-runs the full rescan selection every sweep** (#5992). The earlier fix skipped a rescan only for the artifact row whose upload or push scan was queued, while a rescan covers every row holding the digest, so a second row could still pull the digest in beside the queued scan. It also kept the selection from ever being remembered as finished while any hosted scan was queued, which on an instance with steady uploads re-ran the full stale-digest query every 30 seconds. Now the whole digest is held back, and the selection is remembered as finished unless a rescan is still queued or a stale digest was held back.
