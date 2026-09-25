---
section: Added
issues: [#4277]
---
- **Age gate withholds too-new upstream packages on generic proxy download paths** (#4277). Formats without a dedicated handler (Maven, RubyGems, Debian, and others) now parse identity from the path on the shared remote/virtual download seam; index and checksum paths stay reachable.
