---
section: Fixed
issues: [#4819]
---
- **Make DATABASE_URL_FILE take effect in the published backend image** (#4819). The baked-in `DATABASE_URL=set-database-url-at-runtime` placeholder no longer prevents the `_FILE` form from being used; `DATABASE_URL` can also be left unset entirely.
