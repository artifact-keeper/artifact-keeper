---
section: Fixed
issues: [#5147]
---
- **NuGet virtual repositories resolve imported mixed-case package names** (#5147). Local member downloads now match IDs case-insensitively, as direct local downloads already do, while retaining download gates and the stored path. Other package formats keep their existing matching rules.
