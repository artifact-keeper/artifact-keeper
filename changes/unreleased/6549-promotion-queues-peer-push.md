---
section: Fixed
issues: [#6549]
---
- **A promoted artifact is pushed to the target repository's subscribed peers right away** (#6549). Uploads queued a push task for every push or mirror peer subscription, but the single, bulk and approval promote routes did not, so a promoted artifact reached the peer only on the subscription's next scheduled sync, or never without a schedule. All three routes now queue it the way an upload does. For a Docker/OCI manifest the sync worker sends the blobs with it.
