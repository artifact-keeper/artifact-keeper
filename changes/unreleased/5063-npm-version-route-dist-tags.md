---
section: Fixed
issues: [#5063]
---
- **npm: the version route resolves dist-tags** (#5063). `GET /npm/{repo}/{package}/{version}` (and the scoped form) answered 404 for a dist-tag such as `latest` or `next`, on Local, Remote and Virtual repositories. When no version of that name exists, the segment is now resolved through the package's `dist-tags`, as the npm registry does; an exact version still wins over a tag of the same name, and an unknown tag is still 404. On a Local repository the stored tags are used, with `latest` derived from the versions when none is stored.
