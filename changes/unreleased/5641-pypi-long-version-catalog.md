---
section: Fixed
issues: [#5641]
---
- **PyPI versions longer than 128 characters are cataloged instead of silently dropped from the package listing** (#5641). `packages.version` and `package_versions.version` were `VARCHAR(128)` (migration 211), so a `twine upload` of a wheel with a longer PEP 440 local version answered 200 and served the file, but the best-effort catalog upsert failed with `value too long for type character varying(128)` and the version never appeared under `GET /api/v1/packages/{id}/versions`. Both columns are `TEXT` now, matching the scanner text columns widened in migrations 339 and 342.
