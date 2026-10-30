---
section: Fixed
issues: [#5128]
---
- **Stop a racing repodata fold from rebuilding an unchanged RPM root** (#5128). A dirty mark that a concurrent fold read before a build cleared the queue could be applied after the build, asking for a redundant revision even though the mark was already in the build's snapshot. The fold now compares marks with the build's claim instant, and the reconcile no longer dirties a root whose build is still in flight.
