---
section: Fixed
issues: [#4367]
---
- **Maven `.meta/prefixes.txt` no longer lists nested groupIds, which made Maven 4 deny artifacts the repository serves** (#4367). Entries whose parent prefix is already listed are now left out.
