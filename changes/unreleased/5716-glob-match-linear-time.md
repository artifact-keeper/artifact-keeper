---
section: Fixed
issues: [#5716]
---
- **A curation or npm scope-policy pattern with many `*` wildcards no longer stalls package requests** (#5716). The glob matcher tried every way of dividing the name between the wildcards, so the time to reject a non-matching name grew exponentially with the number of `*`: a six-wildcard pattern took ten seconds against a 120-character package name. It now matches in time proportional to the pattern length times the name length. Which names a pattern matches is unchanged.
