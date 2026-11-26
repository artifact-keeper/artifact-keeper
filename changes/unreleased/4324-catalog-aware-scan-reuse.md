---
section: Fixed
issues: [#4324]
---
- **An upload that expects a catalog no longer takes over a clean verdict graded without one** (#4324). Scan reuse matched on bytes, scanner and pin, so the same bytes first uploaded as a file whose format expects no catalog (where an empty catalog is a complete clean) handed that clean to a later upload as an archive or package, whose empty catalog means nothing was assessed. Such an upload now keeps its own earlier verdict if it has one and scans otherwise. A verdict with findings, and the artifact's own verdict, are reused as before
