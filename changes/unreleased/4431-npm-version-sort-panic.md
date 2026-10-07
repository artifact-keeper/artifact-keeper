---
section: Fixed
issues: [#4431]
---
- **An npm package that mixes numeric and hash prerelease versions no longer panics its packument request through an age-gated repository** (#4431). `confusing-browser-globals` publishes `2.0.0-next.74`, `-next.103` and `-next.2150693d`, and the version comparator ordered them `74 < 103 < 2150693d < 74`: numeric between two numbers, lexical otherwise. `sort_by` panicked on that cycle, the connection dropped, and every request for the package failed. Version segments are now compared in natural order: leading digits by value, then the rest lexically. npm prerelease identifiers follow SemVer 2.0.0 §11.4.3, where a numeric identifier ranks below an alphanumeric one. The curation comparator behind the Hex, NuGet and package version listings had the same cycle and uses the same natural order.
