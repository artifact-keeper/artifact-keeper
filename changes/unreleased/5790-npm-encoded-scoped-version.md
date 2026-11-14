---
section: Fixed
issues: [#5790]
---
- **`GET /npm/{repo}/@scope%2fname/{version}` answers the version document instead of `400`** (#5790). With the scope separator percent-encoded the request matched the scoped packument route with the decoded scope `scope/name` and the version as the package name, and the rebuilt `@scope/name/1.0.0` failed the name check with "Scoped package name must have exactly one '/'". That shape now splits off the version and serves `/{version}` (a dist-tag such as `latest` too) on Local, Remote and Virtual repositories, as the unencoded `@scope/name/{version}` already did.
