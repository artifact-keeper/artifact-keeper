---
section: Fixed
issues: [#6548]
---
- **A Virtual Debian repository with Local members serves their packages** (#6548). When no Remote member answered, `Release`, `InRelease`, `Release.gpg` and the `Packages` indexes were built from the Virtual's own artifacts, of which it has none, so apt got a correctly signed, empty index. They are now built from the Local and Staging members the caller may read, in priority order. A pool path two members share lists the first member's copy, the one a download through the Virtual returns. A Virtual with no readable member answers 404 instead of signing an empty index, and one with only Remote members that did not answer answers 404 too
