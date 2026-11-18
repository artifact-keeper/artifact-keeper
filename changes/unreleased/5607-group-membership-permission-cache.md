---
section: Fixed
issues: [#5607]
---
- **Adding or removing group members, and deleting a group, takes effect at once on the replica that served it** (#5607). The group handlers relied on the cross-replica invalidation NOTIFY alone, so where that path was not delivered a removed member kept the group's grants for up to the 30 s permission cache. They now flush the local permission cache like the permission and project handlers do. Other replicas still rely on the NOTIFY.
