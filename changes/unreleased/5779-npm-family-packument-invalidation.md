---
section: Fixed
issues: [#5779]
---
- **A deleted version of a `yarn`, `pnpm` or `bower` package leaves the Virtual packument straight away** (#5779). These repositories are served by the npm handler and its packument cache, but the post-delete steps matched the `npm` format only: a retention sweep, a REST artifact delete or a trash restore in such a Local left the Virtual serving the old version list for the cache's fresh window (300 s by default), and a delete or retention sweep there left dist-tags naming the removed version. They now cover every npm-family format.
