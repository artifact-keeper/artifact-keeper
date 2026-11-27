---
section: Fixed
issues: [#6514]
---
- **VSCodium and VS Code can search a hosted VS Code extension repository** (#6514). The gallery answer carried no `flags` on each extension, and the clients read it as a string to tell preview extensions apart, so the search failed with `Error while fetching extensions`. Every hosted extension now carries `"flags": "public"`
