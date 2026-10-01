---
section: Fixed
issues: [#3955]
---
- **npm virtual repositories no longer fail `npm install` with EINTEGRITY when a hosted member holds the same `name@version` as a higher-priority remote member** (#3955). The packument merge honours member priority (the highest-priority member's `dist.integrity` wins per version) but the tarball route's dependency-confusion guard suppressed every Remote member whenever any non-Remote member owned the exact version, so the advertised integrity and the served bytes came from different members. Following the priority rule PyPI adopted in #2311, the guard now suppresses a Remote member only when an owning non-Remote member outranks it; the name-only fail-safe for unparseable tarball filenames is unchanged.
